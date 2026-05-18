from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vol_for_smes.volatility import os_detection
from vol_for_smes.utils.helpers import parse_info_rows


def test_parse_info_rows_accepts_dict_output():
    rows, parsed = parse_info_rows({"NtMajorVersion": 10})

    assert rows == [{"Variable": "NtMajorVersion", "Value": 10}]
    assert parsed == {"ntmajorversion": 10}


def test_parse_info_rows_accepts_list_output():
    rows, parsed = parse_info_rows(
        [{"Name": "Is64Bit", "value": "True"}, {"Key": "Kernel Base", "Value": "0x1"}]
    )

    assert len(rows) == 2
    assert parsed["is64bit"] == "True"
    assert parsed["kernel base"] == "0x1"


def test_parse_info_rows_ignores_non_dict_rows_and_empty_keys():
    rows, parsed = parse_info_rows([['bad'], {"Variable": "", "Value": 1}])

    assert rows == [["bad"], {"Variable": "", "Value": 1}]
    assert parsed == {}


def test_parse_info_rows_returns_empty_for_invalid_data():
    assert parse_info_rows("bad") == ([], {})


@patch("vol_for_smes.volatility.os_detection.resolve_volatility_command")
@patch("vol_for_smes.volatility.os_detection.discover_volatility_commands")
def test_candidate_commands_includes_given_command_and_discovered_commands(
    mock_discover,
    mock_resolve,
):
    mock_discover.return_value = [["vol"], ["fallback-vol"]]

    assert os_detection._candidate_commands(["custom"]) == [["custom"], ["vol"], ["fallback-vol"]]
    mock_resolve.assert_not_called()


@patch("vol_for_smes.volatility.os_detection.resolve_volatility_command")
@patch("vol_for_smes.volatility.os_detection.discover_volatility_commands")
def test_candidate_commands_uses_resolve_when_no_command_found(mock_discover, mock_resolve):
    mock_discover.side_effect = RuntimeError("missing")
    mock_resolve.return_value = ["resolved"]

    assert os_detection._candidate_commands("vol") == [["resolved"]]


@patch("vol_for_smes.volatility.os_detection._default_volatility_args", return_value=["--cache-path", "cache"])
@patch("vol_for_smes.volatility.os_detection.parse_json_output")
@patch("vol_for_smes.volatility.os_detection.run_subprocess")
@patch("vol_for_smes.volatility.os_detection.build_volatility_command")
def test_detect_with_windows_info_returns_windows_details(mock_build, mock_run, mock_parse, _mock_args):
    mock_build.return_value = [
        "vol",
        "--cache-path",
        "cache",
        "--renderer",
        "json",
        "-f",
        "memory.raw",
        "windows.info",
    ]
    mock_run.return_value = SimpleNamespace(returncode=0, stdout="[]", stderr="")
    mock_parse.return_value = [
        {"Variable": "Kernel Base", "Value": "0xf8000000"},
        {"Variable": "Is64Bit", "Value": "True"},
        {"Variable": "NtMajorVersion", "Value": 10},
        {"Variable": "NtMinorVersion", "Value": 0},
        {"Variable": "NtProductType", "Value": "WinNt"},
    ]

    result = os_detection._detect_with_windows_info("memory.raw", ["vol"])

    assert result["os"] == "Windows"
    assert result["detected_with"] == "windows.info"
    assert result["architecture"] == "x64"
    assert result["major_version"] == 10
    assert result["volatility_args"] == ["--cache-path", "cache"]
    mock_build.assert_called_once_with(
        ["vol"],
        ["--cache-path", "cache", "--renderer", "json", "-f", "memory.raw", "windows.info"],
    )


@patch("vol_for_smes.volatility.os_detection.parse_json_output", return_value=[])
@patch("vol_for_smes.volatility.os_detection._default_volatility_args", return_value=["--cache-path", "cache"])
@patch("vol_for_smes.volatility.os_detection.run_subprocess")
@patch("vol_for_smes.volatility.os_detection.build_volatility_command", return_value=["vol"])
def test_detect_with_windows_info_returns_unknown_when_no_rows(_, mock_run, __, ___):
    mock_run.return_value = SimpleNamespace(returncode=0, stdout="[]", stderr="")

    assert os_detection._detect_with_windows_info("memory.raw", ["vol"]) == {
        "os": "Unknown",
        "details": "No OS information found",
    }


@patch("vol_for_smes.volatility.os_detection._default_volatility_args", return_value=["--cache-path", "cache"])
@patch("vol_for_smes.volatility.os_detection.run_subprocess")
@patch("vol_for_smes.volatility.os_detection.build_volatility_command", return_value=["vol"])
def test_detect_with_windows_info_raises_on_plugin_failure(_, mock_run, __):
    mock_run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="failed")

    with pytest.raises(RuntimeError, match="failed"):
        os_detection._detect_with_windows_info("memory.raw", ["vol"])


@patch("vol_for_smes.volatility.os_detection._candidate_commands")
def test_detect_os_returns_unknown_when_candidate_resolution_fails(mock_candidates):
    mock_candidates.side_effect = RuntimeError("not installed")

    assert os_detection.detect_os("memory.raw") == {"os": "Unknown", "error": "not installed"}


@patch("vol_for_smes.volatility.os_detection._detect_with_windows_info")
@patch("vol_for_smes.volatility.os_detection._candidate_commands")
def test_detect_os_uses_windows_info_detection(mock_candidates, mock_detect_windows_info):
    mock_candidates.return_value = [["vol"]]
    mock_detect_windows_info.return_value = {"os": "Windows"}

    assert os_detection.detect_os("memory.raw") == {"os": "Windows"}
    mock_detect_windows_info.assert_called_once_with(
        "memory.raw",
        ["vol"],
        cancel_event=None,
    )


@patch("vol_for_smes.volatility.os_detection._detect_with_windows_info")
@patch("vol_for_smes.volatility.os_detection._candidate_commands")
def test_detect_os_tries_all_candidates_before_returning_unknown(
    mock_candidates,
    mock_detect_windows_info,
):
    mock_candidates.return_value = [["vol-a"], ["vol-b"]]
    mock_detect_windows_info.side_effect = [RuntimeError("bad a"), RuntimeError("bad b")]

    result = os_detection.detect_os("memory.raw")

    assert result["os"] == "Unknown"
    assert "[vol-a] bad a" in result["error"]
    assert "[vol-b] bad b" in result["error"]
