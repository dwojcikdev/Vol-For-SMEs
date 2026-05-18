from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from vol_for_smes.volatility import volatility_runner


def make_runner(os_context=None):
    with patch(
        "vol_for_smes.volatility.volatility_runner.resolve_volatility_command",
        return_value=["vol"],
    ), patch(
        "vol_for_smes.volatility.volatility_runner.get_volatility_cache_dir",
        return_value="cache-dir",
    ):
        return volatility_runner.VolatilityRunner("memory.raw", os_context=os_context)


@patch("vol_for_smes.volatility.volatility_runner.resolve_volatility_command")
def test_init_resolves_command(mock_resolve):
    mock_resolve.return_value = ["vol"]

    runner = volatility_runner.VolatilityRunner("memory.raw")

    assert runner.memory_path == "memory.raw"
    assert runner.volatility_command == ["vol"]


@patch("vol_for_smes.volatility.volatility_runner.resolve_volatility_command")
def test_init_uses_os_context_command(mock_resolve):
    runner = volatility_runner.VolatilityRunner(
        "memory.raw",
        os_context={
            "volatility_command": ["custom-vol"],
        },
    )

    assert runner.volatility_command == ["custom-vol"]
    mock_resolve.assert_not_called()


@patch("vol_for_smes.volatility.volatility_runner.get_volatility_cache_dir", return_value="cache-dir")
def test_base_args_use_json_renderer(_mock_cache_dir):
    runner = make_runner()

    assert runner._base_args() == [
        "--cache-path",
        "cache-dir",
        "--renderer",
        "json",
        "-f",
        "memory.raw",
    ]


@patch("vol_for_smes.volatility.volatility_runner.get_volatility_cache_dir", return_value="cache-dir")
def test_base_args_include_extra_args(_mock_cache_dir):
    runner = make_runner(
        os_context={
            "volatility_command": ["vol"],
            "volatility_args": ["--single-location", "file:///symbols"],
        }
    )

    assert runner._base_args() == [
        "--cache-path",
        "cache-dir",
        "--renderer",
        "json",
        "--single-location",
        "file:///symbols",
        "-f",
        "memory.raw",
    ]


@patch("vol_for_smes.volatility.volatility_runner.parse_json_output")
@patch("vol_for_smes.volatility.volatility_runner.run_subprocess")
@patch("vol_for_smes.volatility.volatility_runner.get_volatility_cache_dir", return_value="cache-dir")
@patch("vol_for_smes.volatility.volatility_runner.build_volatility_command")
def test_run_plugin_builds_command_and_returns_parsed_json(
    mock_build,
    _mock_cache_dir,
    mock_run_subprocess,
    mock_parse,
):
    runner = make_runner()
    mock_build.return_value = ["vol", "--renderer", "json", "-f", "memory.raw", "windows.pslist"]
    mock_run_subprocess.return_value = SimpleNamespace(returncode=0, stdout='[{"PID": 4}]', stderr="")
    mock_parse.return_value = [{"PID": 4}]

    assert runner.run_plugin("windows.pslist") == [{"PID": 4}]
    mock_build.assert_called_once_with(
        ["vol"],
        ["--cache-path", "cache-dir", "--renderer", "json", "-f", "memory.raw", "windows.pslist"],
    )
    mock_run_subprocess.assert_called_once()
    assert mock_run_subprocess.call_args.kwargs["cancel_event"] is runner._cancel_requested
    assert mock_run_subprocess.call_args.kwargs["on_process_start"] == runner._register_process
    assert mock_run_subprocess.call_args.kwargs["on_process_end"] == runner._unregister_process
    mock_parse.assert_called_once_with('[{"PID": 4}]')
    assert runner.latest_raw_outputs["windows.pslist"] == {
        "command": ["vol", "--renderer", "json", "-f", "memory.raw", "windows.pslist"],
        "returncode": 0,
        "stdout": '[{"PID": 4}]',
        "stderr": "",
    }


@patch("vol_for_smes.volatility.volatility_runner.parse_json_output")
@patch("vol_for_smes.volatility.volatility_runner.run_subprocess")
@patch("vol_for_smes.volatility.volatility_runner.get_volatility_cache_dir", return_value="cache-dir")
@patch("vol_for_smes.volatility.volatility_runner.build_volatility_command")
def test_run_multiple_retains_exact_per_plugin_output(
    mock_build,
    _mock_cache_dir,
    mock_run_subprocess,
    mock_parse,
):
    runner = make_runner()
    mock_build.side_effect = lambda base, extra: list(base) + list(extra)
    mock_run_subprocess.side_effect = [
        SimpleNamespace(returncode=0, stdout='[{"PID": 4}]', stderr=""),
        SimpleNamespace(returncode=0, stdout='[{"PID": 8}]', stderr="warning"),
    ]
    mock_parse.side_effect = [
        [{"PID": 4}],
        [{"PID": 8}],
    ]

    results = runner.run_multiple(["windows.pslist", "windows.psscan"], max_workers=1)

    assert results == {
        "windows.pslist": [{"PID": 4}],
        "windows.psscan": [{"PID": 8}],
    }
    assert runner.latest_raw_outputs["windows.pslist"]["stdout"] == '[{"PID": 4}]'
    assert runner.latest_raw_outputs["windows.psscan"]["stdout"] == '[{"PID": 8}]'
    assert runner.latest_raw_outputs["windows.psscan"]["stderr"] == "warning"

@patch("vol_for_smes.volatility.volatility_runner.run_subprocess")
@patch("vol_for_smes.volatility.volatility_runner.build_volatility_command", return_value=["vol"])
def test_run_plugin_raises_when_command_is_missing(_, mock_run_subprocess):
    runner = make_runner()
    mock_run_subprocess.side_effect = FileNotFoundError

    with pytest.raises(RuntimeError, match="was not found"):
        runner.run_plugin("windows.pslist")


@patch("vol_for_smes.volatility.volatility_runner.run_subprocess")
@patch("vol_for_smes.volatility.volatility_runner.build_volatility_command", return_value=["vol"])
def test_run_plugin_raises_when_process_fails(_, mock_run_subprocess):
    runner = make_runner()
    mock_run_subprocess.return_value = SimpleNamespace(returncode=1, stdout="", stderr="plugin failed")

    with pytest.raises(RuntimeError, match="plugin failed"):
        runner.run_plugin("windows.pslist")


@patch("vol_for_smes.volatility.volatility_runner.parse_json_output")
@patch("vol_for_smes.volatility.volatility_runner.run_subprocess")
@patch("vol_for_smes.volatility.volatility_runner.build_volatility_command", return_value=["vol"])
def test_run_plugin_raises_when_json_is_invalid(_, mock_run_subprocess, mock_parse):
    runner = make_runner()
    mock_run_subprocess.return_value = SimpleNamespace(returncode=0, stdout="bad", stderr="")
    mock_parse.side_effect = ValueError("bad json")

    with pytest.raises(RuntimeError, match="invalid JSON"):
        runner.run_plugin("windows.pslist")


@patch("vol_for_smes.volatility.volatility_runner.run_subprocess")
@patch("vol_for_smes.volatility.volatility_runner.build_volatility_command", return_value=["vol"])
def test_run_plugin_raises_when_cancelled(_, mock_run_subprocess):
    runner = make_runner()
    mock_run_subprocess.side_effect = InterruptedError("Operation cancelled.")

    with pytest.raises(volatility_runner.VolatilityRunCancelled, match="cancelled"):
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


@patch("builtins.print")
def test_run_multiple_prints_concise_status_messages(mock_print):
    runner = make_runner()
    runner.run_plugin = MagicMock(return_value={"plugin": "windows.pslist"})

    runner.run_multiple(["windows.pslist"], max_workers=1)

    printed = "\n".join(call.args[0] for call in mock_print.call_args_list if call.args)
    assert "(0/1) [windows.pslist] running at 00m " in printed
    assert "(1/1) [windows.pslist] successfully finished at 00m " in printed
    assert "plugin runtime 00m " in printed
    assert "T+" not in printed
    assert "[####################] (1/1) 1 plugins out of 1 executed successfully" in printed
    assert "Output for windows.pslist" not in printed


@patch("builtins.print")
def test_run_multiple_prints_failed_message_on_error(mock_print):
    runner = make_runner()
    runner.run_plugin = MagicMock(side_effect=RuntimeError("failed"))

    runner.run_multiple(["windows.pslist"], max_workers=1)

    printed = "\n".join(call.args[0] for call in mock_print.call_args_list if call.args)
    assert "(1/1) [windows.pslist] failed at 00m " in printed
    assert "plugin runtime 00m " in printed
    assert "T+" not in printed
    assert "(1/1) [windows.pslist] This plugin could not be completed." in printed


def test_run_multiple_emits_progress_events():
    runner = make_runner()
    runner.run_plugin = MagicMock(return_value={"plugin": "windows.pslist"})
    progress_events = []

    runner.run_multiple(
        ["windows.pslist"],
        max_workers=1,
        progress_callback=progress_events.append,
    )

    assert [event["state"] for event in progress_events] == [
        "pending",
        "running",
        "completed",
        "finished",
    ]
    assert progress_events[0]["running_plugins"] == []
    assert progress_events[1]["running_plugins"] == ["windows.pslist"]
    assert progress_events[2]["running_plugins"] == []
    assert progress_events[3]["running_plugins"] == []
    assert progress_events[1]["started_offset_seconds"] >= 0
    assert progress_events[2]["started_offset_seconds"] >= 0
    assert progress_events[2]["finished_offset_seconds"] >= progress_events[2]["started_offset_seconds"]
    assert progress_events[3]["finished_offset_seconds"] >= progress_events[2]["finished_offset_seconds"]
    assert progress_events[-1]["completed"] == 1
    assert progress_events[-1]["total"] == 1


@patch("builtins.print")
def test_run_multiple_records_plugin_execution_log(_mock_print):
    runner = make_runner()
    runner.run_plugin = MagicMock(return_value={"plugin": "windows.pslist"})

    runner.run_multiple(["windows.pslist"], max_workers=1)

    assert len(runner.latest_plugin_execution_log) == 1
    log_entry = runner.latest_plugin_execution_log[0]
    assert log_entry["plugin"] == "windows.pslist"
    assert log_entry["status"] == "completed"
    assert log_entry["success"] is True
    assert log_entry["started_offset_seconds"] >= 0
    assert log_entry["finished_offset_seconds"] >= log_entry["started_offset_seconds"]
    assert runner.latest_execution_elapsed_seconds >= log_entry["finished_offset_seconds"]


def test_format_elapsed_uses_minute_second_labels():
    runner = make_runner()

    assert runner._format_elapsed(3.57) == "00m 03.57s"
    assert runner._format_elapsed(65.5) == "01m 05.50s"
    assert runner._format_timeline_offset(65.5) == "01m 05.50s"


@patch("builtins.print")
def test_run_multiple_stops_when_cancelled(_mock_print):
    runner = make_runner()
    progress_events = []

    def cancel_run(_plugin):
        runner.cancel()
        raise volatility_runner.VolatilityRunCancelled("Investigation was cancelled.")

    runner.run_plugin = MagicMock(side_effect=cancel_run)

    with pytest.raises(volatility_runner.VolatilityRunCancelled, match="cancelled"):
        runner.run_multiple(
            ["windows.pslist"],
            max_workers=1,
            progress_callback=progress_events.append,
        )

    assert [event["state"] for event in progress_events] == [
        "pending",
        "running",
    ]


def test_cancel_terminates_active_processes():
    runner = make_runner()

    class FakeProcess:
        def __init__(self):
            self.terminated = False

        def terminate(self):
            self.terminated = True

    first = FakeProcess()
    second = FakeProcess()
    runner._active_processes = {first, second}

    runner.cancel()

    assert runner._cancel_requested.is_set() is True
    assert first.terminated is True
    assert second.terminated is True
