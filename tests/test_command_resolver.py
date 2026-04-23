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


@patch("vol_for_smes.utils.file_utils.get_project_root")
def test_volatility_installation_root_is_under_project_root(mock_root):
    mock_root.return_value = Path("project")

    assert (
        file_utils.get_volatility_installation_root()
        == Path("project") / "volatility_installation"
    )


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
def test_discover_installation_command_returns_first_discovered_command(mock_discover):
    mock_discover.return_value = [["vol3"], ["vol2"]]

    assert command_resolver._discover_installation_command() == ["vol3"]


@patch("vol_for_smes.volatility.command_resolver.discover_volatility_commands")
@patch("vol_for_smes.volatility.command_resolver._volatility_installation_root")
def test_discover_installation_command_raises_when_no_command_found(
    mock_root,
    mock_discover,
):
    mock_root.return_value = Path("missing_install")
    mock_discover.return_value = []

    with pytest.raises(RuntimeError, match="No runnable Volatility executable"):
        command_resolver._discover_installation_command()


@patch("vol_for_smes.volatility.command_resolver.can_invoke_command", return_value=True)
def test_discover_volatility_commands_finds_supported_entrypoints(_, tmp_path):
    (tmp_path / "vol.exe").write_text("", encoding="utf-8")
    (tmp_path / "vol.py").write_text("", encoding="utf-8")
    (tmp_path / "volatility_2.6.exe").write_text("", encoding="utf-8")
    (tmp_path / "other.exe").write_text("", encoding="utf-8")

    with patch(
        "vol_for_smes.volatility.command_resolver._volatility_installation_root",
        return_value=tmp_path,
    ), patch(
        "vol_for_smes.volatility.command_resolver._resolve_script_command",
        return_value=["python", str(tmp_path / "vol.py")],
    ):
        commands = command_resolver.discover_volatility_commands()

    assert [str(tmp_path / "vol.exe")] in commands
    assert ["python", str(tmp_path / "vol.py")] in commands
    assert [str(tmp_path / "volatility_2.6.exe")] in commands
    assert [str(tmp_path / "other.exe")] not in commands


def test_discover_volatility_commands_raises_when_installation_folder_missing(tmp_path):
    missing_root = tmp_path / "missing"

    with patch(
        "vol_for_smes.volatility.command_resolver._volatility_installation_root",
        return_value=missing_root,
    ):
        with pytest.raises(RuntimeError, match="folder was not found"):
            command_resolver.discover_volatility_commands()


@patch("vol_for_smes.volatility.command_resolver._discover_installation_command")
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


@patch("vol_for_smes.volatility.command_resolver._discover_installation_command")
@patch("vol_for_smes.volatility.command_resolver.can_invoke_command")
def test_resolve_volatility_command_falls_back_to_path_command(mock_can_invoke, mock_discover):
    mock_discover.side_effect = RuntimeError("missing bundled install")
    mock_can_invoke.side_effect = [False, True]

    assert command_resolver.resolve_volatility_command() == ["volatility"]


def test_build_volatility_command_combines_command_and_args():
    assert command_resolver.build_volatility_command(
        ["vol"],
        ["-f", "memory.raw"],
    ) == ["vol", "-f", "memory.raw"]


@patch("vol_for_smes.volatility.command_resolver.subprocess.run")
def test_detect_volatility_variant_identifies_vol3(mock_run):
    mock_run.return_value = SimpleNamespace(
        stdout="Volatility 3 Framework",
        stderr="",
    )

    assert command_resolver.detect_volatility_variant(["vol"]) == "vol3"


@patch("vol_for_smes.volatility.command_resolver.subprocess.run")
def test_detect_volatility_variant_identifies_vol2(mock_run):
    mock_run.return_value = SimpleNamespace(
        stdout="",
        stderr="Volatility Foundation Volatility Framework 2",
    )

    assert command_resolver.detect_volatility_variant(["volatility"]) == "vol2"


@patch("vol_for_smes.volatility.command_resolver.subprocess.run")
def test_detect_volatility_variant_returns_unknown_on_execution_error(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["vol"], timeout=15)

    assert command_resolver.detect_volatility_variant(["vol"]) == "unknown"


def test_parse_json_output_reads_json_after_prefix_text():
    assert command_resolver.parse_json_output('warning\n[{"PID": 4}]') == [{"PID": 4}]


def test_parse_json_output_rejects_empty_text():
    with pytest.raises(json.JSONDecodeError):
        command_resolver.parse_json_output("  ")


def test_parse_json_output_rejects_text_without_json():
    with pytest.raises(json.JSONDecodeError):
        command_resolver.parse_json_output("not json")
