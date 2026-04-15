from vol_for_smes.volatility import results_parser


def test_extract_rows_returns_list_input_unchanged():
    rows = [{"PID": 4}]

    assert results_parser.extract_rows(rows) is rows


def test_extract_rows_returns_legacy_rows():
    assert results_parser.extract_rows({"rows": [[0, 4]]}) == [[0, 4]]


def test_extract_rows_returns_empty_list_when_rows_missing():
    assert results_parser.extract_rows({"columns": []}) == []


def test_parse_processes_parses_vol3_dict_rows():
    result = results_parser.parse_processes(
        [{"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 100}]
    )

    assert result == [{"pid": 4, "ppid": 0, "name": "System", "threads": 100}]


def test_parse_processes_parses_lowercase_and_name_keys():
    result = results_parser.parse_processes(
        [{"pid": 123, "ppid": 4, "Name": "cmd.exe", "threads": 2}]
    )

    assert result == [{"pid": 123, "ppid": 4, "name": "cmd.exe", "threads": 2}]


def test_parse_processes_parses_legacy_list_rows():
    result = results_parser.parse_processes({"rows": [["offset", 10, 4, "explorer.exe", 20]]})

    assert result == [{"pid": 10, "ppid": 4, "name": "explorer.exe", "threads": 20}]


def test_parse_processes_handles_short_legacy_rows():
    result = results_parser.parse_processes({"rows": [["offset", 10]]})

    assert result == [{"pid": 10, "ppid": None, "name": None, "threads": None}]
