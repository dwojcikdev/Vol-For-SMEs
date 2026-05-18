from pathlib import Path
from tempfile import TemporaryDirectory

from vol_for_smes.gui import runtime_launcher


def test_append_log_path_leaves_message_unchanged_without_log():
    assert runtime_launcher._append_log_path("message", None) == "message"


def test_append_log_path_includes_crash_log_location():
    scratch_root = Path.cwd() / ".test-scratch"
    scratch_root.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=scratch_root) as raw_path:
        log_path = Path(raw_path) / "Logs" / "crash.log"

        message = runtime_launcher._append_log_path("message", log_path)

        assert "message" in message
        assert str(log_path) in message
