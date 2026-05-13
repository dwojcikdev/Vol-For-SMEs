import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vol_for_smes.volatility import command_resolver
from vol_for_smes.utils import file_utils, helpers


@patch("vol_for_smes.utils.helpers.subprocess.run")
def test_can_invoke_returns_true_for_zero_exit(mock_run):
    mock_run.return_value = SimpleNamespace(returncode=0, stdout="help", stderr="")

    assert helpers.can_invoke_command(["vol"])
    mock_run.assert_called_once_with(
        ["vol", "-h"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=8,
        check=False,
    )


@patch("vol_for_smes.utils.helpers.subprocess.run")
def test_can_invoke_accepts_usage_output_for_nonzero_exit(mock_run):
    mock_run.return_value = SimpleNamespace(
        returncode=2,
        stdout="Usage: vol [options]",
        stderr="",
    )

    assert helpers.can_invoke_command(["vol"])


@patch("vol_for_smes.utils.helpers.subprocess.run")
def test_can_invoke_rejects_missing_module_output(mock_run):
    mock_run.return_value = SimpleNamespace(
        returncode=1,
        stdout="",
        stderr="No module named volatility3",
    )

    assert not helpers.can_invoke_command(["python", "vol.py"])


@patch("vol_for_smes.utils.helpers.subprocess.run")
def test_can_invoke_returns_false_when_command_fails_to_start(mock_run):
    mock_run.side_effect = FileNotFoundError

    assert not helpers.can_invoke_command(["missing"])


def test_project_root_uses_repository_root():
    expected = Path(command_resolver.__file__).resolve().parents[2]

    assert command_resolver._project_root() == expected


@patch("vol_for_smes.utils.helpers.can_invoke_command")
def test_resolve_script_command_uses_first_working_launcher(mock_can_invoke):
    mock_can_invoke.side_effect = [False, True]
    script_path = Path("tools") / "vol.py"

    assert file_utils.resolve_script_command(script_path) == [
        "python",
        str(script_path),
    ]


@patch("vol_for_smes.utils.helpers.can_invoke_command", return_value=False)
def test_resolve_script_command_returns_none_when_no_launcher_works(_):
    assert file_utils.resolve_script_command(Path("vol.py")) is None


@patch("vol_for_smes.volatility.command_resolver.discover_volatility_commands")
def test_discover_installed_command_returns_first_discovered_command(mock_discover):
    mock_discover.return_value = [["vol"], ["fallback-vol"]]

    assert command_resolver._discover_installed_command() == ["vol"]


@patch("vol_for_smes.volatility.command_resolver.discover_volatility_commands")
def test_discover_installed_command_raises_when_no_command_found(mock_discover):
    mock_discover.return_value = []

    with pytest.raises(RuntimeError, match="No runnable Volatility 3 command was found"):
        command_resolver._discover_installed_command()


@patch("vol_for_smes.volatility.command_resolver.can_invoke_command")
def test_discover_volatility_commands_finds_supported_entrypoints(mock_can_invoke):
    mock_can_invoke.side_effect = [True, False, True]

    commands = command_resolver.discover_volatility_commands()

    assert [command_resolver.sys.executable, "-m", "volatility3.cli"] in commands
    assert ["vol"] not in commands
    assert ["volatility"] in commands


@patch("vol_for_smes.volatility.command_resolver._discover_installed_command")
def test_resolve_volatility_command_uses_discovered_installation(mock_discover):
    mock_discover.return_value = ["vol"]

    assert command_resolver.resolve_volatility_command() == ["vol"]


@patch("vol_for_smes.volatility.command_resolver.can_invoke_command", return_value=True)
def test_resolve_volatility_command_prefers_provided_command(_):
    assert command_resolver.resolve_volatility_command(["custom-vol"]) == ["custom-vol"]


@patch.dict(
    "vol_for_smes.volatility.command_resolver.os.environ",
    {"VOLATILITY_COMMAND": "vol --quiet"},
)
@patch("vol_for_smes.volatility.command_resolver.can_invoke_command", return_value=True)
def test_resolve_volatility_command_uses_environment_command(_):
    assert command_resolver.resolve_volatility_command() == ["vol", "--quiet"]


@patch("vol_for_smes.volatility.command_resolver._discover_installed_command")
def test_resolve_volatility_command_raises_when_no_command_is_available(mock_discover):
    mock_discover.side_effect = RuntimeError("missing dependency")

    with pytest.raises(RuntimeError, match="install the 'volatility3' package"):
        command_resolver.resolve_volatility_command()


def test_build_volatility_command_combines_command_and_args():
    assert command_resolver.build_volatility_command(
        ["vol"],
        ["-f", "memory.raw"],
    ) == ["vol", "-f", "memory.raw"]

def test_parse_json_output_reads_json_after_prefix_text():
    assert command_resolver.parse_json_output('warning\n[{"PID": 4}]') == [{"PID": 4}]


def test_parse_json_output_rejects_empty_text():
    with pytest.raises(json.JSONDecodeError):
        command_resolver.parse_json_output("  ")


def test_parse_json_output_rejects_text_without_json():
    with pytest.raises(json.JSONDecodeError):
        command_resolver.parse_json_output("not json")
