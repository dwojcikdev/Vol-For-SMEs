from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from vol_for_smes.volatility import volatility_runner


def make_runner(variant="vol3", os_context=None):
    with patch(
        "vol_for_smes.volatility.volatility_runner.resolve_volatility_command",
        return_value=["vol"],
    ), patch(
        "vol_for_smes.volatility.volatility_runner.detect_volatility_variant",
        return_value=variant,
    ):
        return volatility_runner.VolatilityRunner("memory.raw", os_context=os_context)


@patch("vol_for_smes.volatility.volatility_runner.detect_volatility_variant")
@patch("vol_for_smes.volatility.volatility_runner.resolve_volatility_command")
def test_init_resolves_command_and_detects_variant(mock_resolve, mock_detect):
    mock_resolve.return_value = ["vol"]
    mock_detect.return_value = "vol3"

    runner = volatility_runner.VolatilityRunner("memory.raw")

    assert runner.memory_path == "memory.raw"
    assert runner.volatility_command == ["vol"]
    assert runner.volatility_variant == "vol3"


@patch("vol_for_smes.volatility.volatility_runner.detect_volatility_variant")
@patch("vol_for_smes.volatility.volatility_runner.resolve_volatility_command")
def test_init_uses_os_context_command_and_variant(mock_resolve, mock_detect):
    runner = volatility_runner.VolatilityRunner(
        "memory.raw",
        os_context={
            "volatility_command": ["custom-vol"],
            "volatility_variant": "vol2",
        },
    )

    assert runner.volatility_command == ["custom-vol"]
    assert runner.volatility_variant == "vol2"
    mock_resolve.assert_not_called()
    mock_detect.assert_not_called()


def test_base_args_for_vol3_uses_json_renderer():
    runner = make_runner("vol3")

    assert runner._base_args() == ["--renderer", "json", "-f", "memory.raw"]


def test_base_args_for_vol2_uses_json_output_and_profile():
    runner = make_runner(
        os_context={
            "volatility_command": ["volatility"],
            "volatility_variant": "vol2",
            "volatility_args": ["--profile=Win10"],
        }
    )

    assert runner._base_args() == ["--output=json", "--profile=Win10", "-f", "memory.raw"]


def test_translate_plugin_maps_vol2_windows_plugin_names():
    runner = make_runner(
        os_context={"volatility_command": ["volatility"], "volatility_variant": "vol2"}
    )

    assert runner._translate_plugin("windows.pslist") == "pslist"
    assert runner._translate_plugin("custom.plugin") == "custom.plugin"


def test_translate_plugin_leaves_vol3_plugin_names_unchanged():
    runner = make_runner("vol3")

    assert runner._translate_plugin("windows.pslist") == "windows.pslist"


@patch("vol_for_smes.volatility.volatility_runner.parse_json_output")
@patch("vol_for_smes.volatility.volatility_runner.subprocess.run")
@patch("vol_for_smes.volatility.volatility_runner.build_volatility_command")
def test_run_plugin_builds_command_and_returns_parsed_json(mock_build, mock_run, mock_parse):
    runner = make_runner("vol3")
    mock_build.return_value = ["vol", "--renderer", "json", "-f", "memory.raw", "windows.pslist"]
    mock_run.return_value = SimpleNamespace(returncode=0, stdout='[{"PID": 4}]', stderr="")
    mock_parse.return_value = [{"PID": 4}]

    assert runner.run_plugin("windows.pslist") == [{"PID": 4}]
    mock_build.assert_called_once_with(
        ["vol"],
        ["--renderer", "json", "-f", "memory.raw", "windows.pslist"],
    )
    mock_parse.assert_called_once_with('[{"PID": 4}]')


@patch("vol_for_smes.volatility.volatility_runner.subprocess.run")
@patch("vol_for_smes.volatility.volatility_runner.build_volatility_command", return_value=["vol"])
def test_run_plugin_raises_when_command_is_missing(_, mock_run):
    runner = make_runner("vol3")
    mock_run.side_effect = FileNotFoundError

    with pytest.raises(RuntimeError, match="was not found"):
        runner.run_plugin("windows.pslist")


@patch("vol_for_smes.volatility.volatility_runner.subprocess.run")
@patch("vol_for_smes.volatility.volatility_runner.build_volatility_command", return_value=["vol"])
def test_run_plugin_raises_when_process_fails(_, mock_run):
    runner = make_runner("vol3")
    mock_run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="plugin failed")

    with pytest.raises(RuntimeError, match="plugin failed"):
        runner.run_plugin("windows.pslist")


@patch("vol_for_smes.volatility.volatility_runner.parse_json_output")
@patch("vol_for_smes.volatility.volatility_runner.subprocess.run")
@patch("vol_for_smes.volatility.volatility_runner.build_volatility_command", return_value=["vol"])
def test_run_plugin_raises_when_json_is_invalid(_, mock_run, mock_parse):
    runner = make_runner("vol3")
    mock_run.return_value = SimpleNamespace(returncode=0, stdout="bad", stderr="")
    mock_parse.side_effect = ValueError("bad json")

    with pytest.raises(RuntimeError, match="invalid JSON"):
        runner.run_plugin("windows.pslist")


@patch("builtins.print")
@patch("vol_for_smes.volatility.volatility_runner.build_volatility_command")
def test_run_multiple_accepts_list_and_collects_results(mock_build, _):
    runner = make_runner()
    runner.run_plugin = MagicMock(side_effect=lambda plugin: {"plugin": plugin})
    mock_build.return_value = ["vol", "plugin"]

    result = runner.run_multiple(["windows.pslist", "windows.cmdline"], max_workers=1)

    assert result == {
        "windows.pslist": {"plugin": "windows.pslist"},
        "windows.cmdline": {"plugin": "windows.cmdline"},
    }


@patch("builtins.print")
@patch("vol_for_smes.volatility.volatility_runner.build_volatility_command")
def test_run_multiple_records_plugin_errors(mock_build, _):
    runner = make_runner()
    runner.run_plugin = MagicMock(side_effect=RuntimeError("failed"))
    mock_build.return_value = ["vol", "plugin"]

    assert runner.run_multiple({"processes": "windows.pslist"}, max_workers=1) == {
        "processes": {"error": "failed"}
    }
