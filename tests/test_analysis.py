from vol_for_smes.analysis import (
    analyse_artefacts,
    analyse_network_activity,
    analyse_plugin_output,
    analyse_process_activity,
    build_timeline,
    load_ransomware_reference_index,
    match_ransomware_references,
)


def test_load_ransomware_reference_index_reads_packaged_csv_resources():
    index = load_ransomware_reference_index()

    assert any(pattern.pattern == "read me please.hta" for pattern in index.exact_patterns)
    assert any(pattern.pattern == "restore_files.txt" for pattern in index.exact_patterns)
    assert any(pattern.pattern == "@wanadecryptor@.exe" for pattern in index.exact_patterns)
    assert any(pattern.pattern == "taskdl.exe" for pattern in index.exact_patterns)
    assert any(pattern.pattern == "*.locked" for pattern in index.suffix_patterns)
    assert not any(pattern.pattern == "*.dll" for pattern in index.suffix_patterns)
    assert not any(pattern.pattern == "*.lock" for pattern in index.suffix_patterns)
    assert not any(pattern.pattern == "*crypt*" for pattern in index.glob_patterns)


def test_match_ransomware_references_matches_notes_and_extensions():
    note_hits = match_ransomware_references(
        r"\Device\HarddiskVolume3\Users\Alice\Desktop\Read Me Please.hta"
    )
    extension_hits = match_ransomware_references(
        r"C:\Users\Alice\Documents\budget.xlsx.locked"
    )

    assert any(hit["source"] == "ransomware_note_names" for hit in note_hits)
    assert any(hit["source"] == "ransomware_file_patterns" for hit in extension_hits)
    assert any(hit["pattern"] == "*.locked" for hit in extension_hits)


def test_match_ransomware_references_handles_short_and_device_paths():
    hits = match_ransomware_references(
        r"\Device\HarddiskVolume3\Users\WIN10~1\Desktop\restore_files.txt"
    )

    assert hits
    assert hits[0]["basename"] == "restore_files.txt"


def test_match_ransomware_references_does_not_match_generic_extension_globs_on_full_paths():
    benign_hits = match_ransomware_references(
        (
            r"\Device\HarddiskVolume3\ProgramData\Microsoft\Windows\AppRepository\Packages"
            r"\Microsoft.Windows.StartMenuExperienceHost_10.0.19041.3636_neutral_neutral_cw5n1h2txyewy"
            r"\ActivationStore.dat.LOG2"
        )
    )
    suspicious_hits = match_ransomware_references(
        r"\Device\HarddiskVolume3\Users\Alice\Desktop\invoice.enc123"
    )

    assert benign_hits == []
    assert any(hit["pattern"] == "*.*enc*" for hit in suspicious_hits)


def test_match_ransomware_references_ignores_generic_system_library_matches():
    hits = match_ransomware_references(
        r"\Device\HarddiskVolume3\Windows\System32\en-GB\crypt32.dll.mui"
    )

    assert hits == []


def test_match_ransomware_references_matches_wannacry_reference_names():
    artefact_hits = match_ransomware_references(
        r"\Device\HarddiskVolume3\Users\Win 10\Downloads\00000000.eky"
    )
    loader_hits = match_ransomware_references(
        r"\Device\HarddiskVolume3\Users\Win 10\Downloads\@WanaDecryptor@.exe"
    )
    cache_hits = match_ransomware_references(
        r"\Device\HarddiskVolume3\Users\WIN10~1\AppData\Local\Temp\361.WNCRYTs\Caches\foo.db"
    )

    assert any(hit["pattern"] == "00000000.eky" for hit in artefact_hits)
    assert any(hit["pattern"] == "@wanadecryptor@.exe" for hit in loader_hits)
    assert any(hit["pattern"] == "*\\*wncry*\\*" for hit in cache_hits)


def test_analyse_plugin_output_flags_suspicious_cmdline():
    result = analyse_plugin_output(
        "windows.cmdline",
        [
            {
                "PID": 4321,
                "ImageFileName": "powershell.exe",
                "CommandLine": "powershell.exe -enc aQBlAHgA",
            }
        ],
    )

    assert result["severity"] == "high"
    assert result["risk_score"] > 0
    assert "cmdline_encoded" in result["rule_ids"]
    assert any(tag["technique_id"] == "T1059.001" for tag in result["mitre_tags"])
    assert result["indicators"]


def test_analyse_plugin_output_ignores_plain_powershell_usage():
    result = analyse_plugin_output(
        "windows.cmdline",
        [
            {
                "PID": 4321,
                "ImageFileName": "powershell.exe",
                "CommandLine": r"powershell.exe -File C:\Admin\collect.ps1",
            }
        ],
    )

    assert result["severity"] == "none"
    assert result["indicators"] == []


def test_analyse_plugin_output_detects_hidden_processes_via_psscan():
    result = analyse_plugin_output(
        "windows.psscan",
        [{"PID": 99, "ImageFileName": "evil.exe"}],
        all_results={"windows.pslist": [{"PID": 4, "ImageFileName": "System"}]},
    )

    assert result["severity"] == "high"
    assert "hidden_process_psscan_only" in result["rule_ids"]
    assert "psscan but not pslist" in result["indicators"][0]


def test_analyse_plugin_output_ignores_benign_microsoft_handle_paths():
    result = analyse_plugin_output(
        "windows.handles",
        [
            {
                "PID": 4,
                "Name": (
                    r"\Device\HarddiskVolume3\ProgramData\Microsoft\Windows"
                    r"\AppRepository\Packages\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c"
                    r"\ActivationStore.dat"
                ),
                "Type": "File",
            }
        ],
    )

    assert result["severity"] == "none"
    assert result["indicators"] == []
    assert result["reference_hits"] == []


def test_analyse_plugin_output_flags_reference_backed_file_activity():
    result = analyse_plugin_output(
        "windows.filescan",
        [
            {
                "Name": r"\Device\HarddiskVolume3\Users\Alice\Desktop\restore_files.txt",
            },
            {
                "Name": r"\Device\HarddiskVolume3\Users\Alice\Documents\budget.xlsx.locked",
            },
        ],
    )

    assert result["severity"] == "medium"
    assert any(tag["technique_id"] == "T1486" for tag in result["mitre_tags"])
    assert len(result["reference_hits"]) == 2


def test_analyse_plugin_output_maps_rule_ids_to_attack_without_keyword_inference():
    result = analyse_plugin_output(
        "windows.handles",
        [
            {
                "PID": 777,
                "Name": r"\REGISTRY\USER\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run",
                "Type": "Key",
            }
        ],
    )

    assert "autorun_registry_key" in result["rule_ids"]
    assert any(tag["technique_id"] == "T1547" for tag in result["mitre_tags"])


def test_build_timeline_extracts_and_sorts_timestamp_events():
    timeline = build_timeline(
        {
            "windows.pslist": [
                {"PID": 100, "ImageFileName": "a.exe", "CreateTime": "2024-01-03 09:00:00 UTC"},
                {"PID": 101, "ImageFileName": "b.exe", "CreateTime": "2024-01-02 09:00:00 UTC"},
            ]
        }
    )

    assert [event["description"] for event in timeline] == [
        "b.exe reported by windows.pslist (CreateTime)",
        "a.exe reported by windows.pslist (CreateTime)",
    ]


def test_build_timeline_preserves_normalised_process_identifiers():
    timeline = build_timeline(
        {
            "windows.pslist": [
                {
                    "pid": "900",
                    "ppid": "400",
                    "name": "powershell.exe",
                    "CreateTime": "2024-01-03 09:00:00 UTC",
                }
            ]
        }
    )

    assert timeline[0]["entity_label"] == "powershell.exe"
    assert timeline[0]["pid"] == 900
    assert timeline[0]["ppid"] == 400


def test_build_timeline_uses_pid_correlation_across_plugins():
    timeline = build_timeline(
        {
            "windows.pslist": [
                {
                    "PID": 444,
                    "PPID": 4,
                    "ImageFileName": "svchost.exe",
                    "CreateTime": "2024-01-03 09:00:00 UTC",
                }
            ],
            "windows.registry.userassist": [
                {
                    "PID": 444,
                    "Created": "2024-01-03 09:05:00 UTC",
                }
            ],
        }
    )

    assert timeline[1]["entity_label"] == "svchost.exe"
    assert timeline[1]["description"] == (
        "svchost.exe reported by windows.registry.userassist (Created)"
    )
    assert timeline[1]["pid"] == 444
    assert timeline[1]["ppid"] == 4


def test_build_timeline_enriches_network_events_with_correlated_process_and_connection():
    timeline = build_timeline(
        {
            "windows.pslist": [
                {
                    "PID": 333,
                    "PPID": 4,
                    "ImageFileName": "powershell.exe",
                    "CreateTime": "2024-01-03 09:00:00 UTC",
                }
            ],
            "windows.netscan": [
                {
                    "PID": 333,
                    "LocalAddr": "10.0.0.5",
                    "LocalPort": 49152,
                    "ForeignAddr": "8.8.8.8",
                    "ForeignPort": 443,
                    "State": "ESTABLISHED",
                    "Created": "2024-01-03 09:02:00 UTC",
                }
            ],
        }
    )

    assert timeline[1]["entity_label"] == "powershell.exe"
    assert timeline[1]["description"] == (
        "powershell.exe (PID 333) 10.0.0.5:49152 -> 8.8.8.8:443 [ESTABLISHED] "
        "reported by windows.netscan (Created)"
    )
    assert timeline[1]["pid"] == 333
    assert timeline[1]["ppid"] == 4


def test_analyse_artefacts_returns_activity_chains_and_suspicious_timeline():
    analysis = analyse_artefacts(
        {
            "windows.pslist": [
                {
                    "PID": 444,
                    "PPID": 3212,
                    "ImageFileName": "suspect.exe",
                    "CreateTime": "2024-01-01 10:00:00 UTC",
                }
            ],
            "windows.pstree": [
                {
                    "PID": 444,
                    "PPID": 3212,
                    "ImageFileName": "suspect.exe",
                    "Path": r"C:\Users\Alice\Downloads\suspect.exe",
                    "CreateTime": "2024-01-01 10:00:00 UTC",
                }
            ],
            "windows.cmdline": [
                {
                    "PID": 444,
                    "ImageFileName": "suspect.exe",
                    "CommandLine": "\"C:\\Users\\Alice\\Downloads\\suspect.exe\"",
                }
            ],
            "windows.handles": [
                {
                    "PID": 444,
                    "Type": "File",
                    "Name": r"C:\Users\Alice\Desktop\restore_files.txt",
                }
            ],
            "windows.malfind": [{"PID": 444, "ImageFileName": "suspect.exe"}],
        }
    )

    assert analysis["risk_summary"]["high"] == 1
    assert analysis["process_analysis"]["severity"] == "high"
    assert analysis["activity_chains"]
    assert analysis["activity_chains"][0]["primary_process"]["pid"] == "444"
    assert analysis["activity_chains"][0]["handle_hits"]
    assert "matched ransomware reference" in analysis["activity_chains"][0]["evidence"][0].lower()
    assert analysis["suspicious_timeline"]


def test_analyse_artefacts_activity_chain_keeps_process_reference_image_hits():
    analysis = analyse_artefacts(
        {
            "windows.pslist": [
                {
                    "PID": 3908,
                    "PPID": 3212,
                    "ImageFileName": "@WanaDecryptor",
                    "CreateTime": "2024-01-01 10:00:00 UTC",
                }
            ],
            "windows.pstree": [
                {
                    "PID": 3908,
                    "PPID": 3212,
                    "ImageFileName": "@WanaDecryptor",
                    "Audit": r"\Device\HarddiskVolume3\Users\Win 10\Downloads\@WanaDecryptor@.exe",
                    "CreateTime": "2024-01-01 10:00:00 UTC",
                }
            ],
        }
    )

    chain = analysis["activity_chains"][0]
    assert chain["reference_hits"]
    assert any(
        hit["path"].endswith("@wanadecryptor@.exe")
        for hit in chain["reference_hits"]
    )
    assert "matched ransomware reference" in chain["evidence"][0].lower()


def test_analyse_process_activity_correlates_multiple_process_indicators():
    analysis = analyse_process_activity(
        {
            "windows.pslist": [
                {"PID": 900, "PPID": 4, "ImageFileName": "powershell.exe"},
            ],
            "windows.cmdline": [
                {"PID": 900, "ImageFileName": "powershell.exe", "CommandLine": "powershell.exe -enc AAAA"},
            ],
            "windows.dlllist": [
                {"PID": 900, "Path": r"C:\\Users\\Public\\payload.dll"},
            ],
            "windows.malfind": [
                {"PID": 900, "ImageFileName": "powershell.exe"},
            ],
        }
    )

    assert analysis["severity"] == "high"
    assert analysis["risk_score"] >= 80
    assert any(tag["technique_id"] == "T1055" for tag in analysis["mitre_tags"])
    assert analysis["suspicious_processes"][0]["pid"] == "900"
    assert analysis["suspicious_processes"][0]["risk_score"] >= 80
    assert any(
        "encoded powershell command" in reason.lower()
        for reason in analysis["suspicious_processes"][0]["reasons"]
    )


def test_analyse_process_activity_includes_handle_hits_and_chain_field():
    analysis = analyse_process_activity(
        {
            "windows.pslist": [
                {"PID": 901, "PPID": 4, "ImageFileName": "random123.exe"},
            ],
            "windows.pstree": [
                {
                    "PID": 901,
                    "PPID": 4,
                    "ImageFileName": "random123.exe",
                    "Path": r"C:\Users\Alice\Downloads\random123.exe",
                }
            ],
            "windows.handles": [
                {
                    "PID": 901,
                    "Type": "File",
                    "Name": r"C:\Users\Alice\Desktop\restore_files.txt",
                }
            ],
        }
    )

    process = analysis["suspicious_processes"][0]
    assert process["handle_hits"]
    assert "process_reference_handle" in process["rule_ids"]
    assert process["chain_id"] == ""


def test_analyse_process_activity_elevates_csv_reference_handle_matches():
    analysis = analyse_process_activity(
        {
            "windows.pslist": [
                {"PID": 902, "PPID": 4, "ImageFileName": "notepad.exe"},
            ],
            "windows.handles": [
                {
                    "PID": 902,
                    "Type": "File",
                    "Name": r"C:\Users\Alice\Desktop\restore_files.txt",
                }
            ],
        }
    )

    process = analysis["suspicious_processes"][0]
    assert analysis["severity"] == "medium"
    assert process["severity"] == "medium"
    assert process["risk_score"] >= 40
    assert "process_reference_handle" in process["rule_ids"]


def test_analyse_process_activity_treats_ransomware_reference_process_image_as_high_risk():
    analysis = analyse_process_activity(
        {
            "windows.pslist": [
                {"PID": 3908, "PPID": 3212, "ImageFileName": "@WanaDecryptor"},
            ],
            "windows.pstree": [
                {
                    "PID": 3908,
                    "PPID": 3212,
                    "ImageFileName": "@WanaDecryptor",
                    "Audit": r"\Device\HarddiskVolume3\Users\Win 10\Downloads\@WanaDecryptor@.exe",
                }
            ],
        }
    )

    process = analysis["suspicious_processes"][0]
    assert analysis["severity"] == "high"
    assert process["severity"] == "high"
    assert process["risk_score"] >= 80
    assert "process_reference_image" in process["rule_ids"]
    assert any(
        hit["path"].endswith("@wanadecryptor@.exe")
        for hit in process["reference_hits"]
    )


def test_analyse_process_activity_flags_ransomware_reference_process_name_without_image_path():
    analysis = analyse_process_activity(
        {
            "windows.pslist": [
                {"PID": 3908, "PPID": 3212, "ImageFileName": "@WanaDecryptor"},
            ],
        }
    )

    process = analysis["suspicious_processes"][0]
    assert analysis["severity"] == "medium"
    assert process["severity"] == "medium"
    assert process["risk_score"] >= 60
    assert "process_reference_name" in process["rule_ids"]
    assert any(
        hit["pattern"] == "@wanadecryptor@.exe"
        for hit in process["reference_hits"]
    )


def test_analyse_artefacts_timeline_keeps_ransomware_reference_process_name_events():
    analysis = analyse_artefacts(
        {
            "windows.pslist": [
                {
                    "PID": 3908,
                    "PPID": 3212,
                    "ImageFileName": "@WanaDecryptor",
                    "CreateTime": "2024-01-01 10:00:00 UTC",
                }
            ],
        }
    )

    assert analysis["suspicious_timeline"]
    assert any(
        "@wanadecryptor" in event["description"].lower()
        for event in analysis["suspicious_timeline"]
    )


def test_analyse_process_activity_includes_hidden_process_findings():
    analysis = analyse_process_activity(
        {
            "windows.pslist": [
                {"PID": 4, "ImageFileName": "System"},
            ],
            "windows.psscan": [
                {"PID": 99, "ImageFileName": "evil.exe"},
            ],
        }
    )

    assert analysis["severity"] == "medium"
    assert analysis["summary"] == "1 suspicious process(es) identified"
    assert analysis["suspicious_processes"][0]["pid"] == "99"
    assert any(
        "psscan but not pslist" in reason.lower()
        for reason in analysis["suspicious_processes"][0]["reasons"]
    )


def test_analyse_process_activity_ignores_legit_microsoft_app_module_paths():
    analysis = analyse_process_activity(
        {
            "windows.pslist": [
                {"PID": 1000, "ImageFileName": "teams.exe"},
            ],
            "windows.dlllist": [
                {
                    "PID": 1000,
                    "Path": r"C:\Users\Alice\AppData\Roaming\Microsoft\Teams\current\Teams.dll",
                }
            ],
        }
    )

    assert analysis["severity"] == "none"
    assert analysis["suspicious_processes"] == []


def test_analyse_network_activity_flags_shell_process_networking():
    analysis = analyse_network_activity(
        {
            "windows.netscan": [
                {
                    "PID": 333,
                    "Owner": "powershell.exe",
                    "LocalAddr": "10.0.0.5",
                    "LocalPort": 49152,
                    "ForeignAddr": "8.8.8.8",
                    "ForeignPort": 443,
                    "State": "ESTABLISHED",
                }
            ]
        }
    )

    assert analysis["severity"] == "high"
    assert analysis["risk_score"] >= 80
    assert any(tag["technique_id"] == "T1071" for tag in analysis["mitre_tags"])
    assert analysis["suspicious_connections"][0]["owner"] == "powershell.exe"


def test_analyse_network_activity_ignores_private_ip_browser_traffic():
    analysis = analyse_network_activity(
        {
            "windows.netscan": [
                {
                    "PID": 777,
                    "Owner": "chrome.exe",
                    "LocalAddr": "10.0.0.5",
                    "LocalPort": 51515,
                    "ForeignAddr": "10.0.0.8",
                    "ForeignPort": 443,
                    "State": "ESTABLISHED",
                }
            ]
        }
    )

    assert analysis["severity"] == "none"
    assert analysis["suspicious_connections"] == []
