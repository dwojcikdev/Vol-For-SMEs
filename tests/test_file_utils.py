from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from vol_for_smes.utils import file_utils


@contextmanager
def _temporary_workspace():
    scratch_root = Path.cwd() / ".test-scratch"
    scratch_root.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=scratch_root) as raw_path:
        yield Path(raw_path)


def test_get_reports_dir_uses_local_app_data(monkeypatch):
    with _temporary_workspace() as tmp_path:
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
        monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))

        assert file_utils.get_reports_dir() == (
            tmp_path / "Local" / "Vol For SMEs" / "Reports"
        )


def test_get_logs_dir_uses_local_app_data(monkeypatch):
    with _temporary_workspace() as tmp_path:
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
        monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))

        assert file_utils.get_logs_dir() == (
            tmp_path / "Local" / "Vol For SMEs" / "Logs"
        )


def test_get_volatility_cache_dir_prefers_local_app_data(monkeypatch):
    with _temporary_workspace() as tmp_path:
        preferred = tmp_path / "Local" / "Vol For SMEs" / "VolatilityCache"
        fallback = tmp_path / "Project" / ".volatility-cache"

        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
        monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
        monkeypatch.setattr(file_utils, "get_project_root", lambda: tmp_path / "Project")
        monkeypatch.setattr(
            file_utils,
            "_ensure_writable_directory",
            lambda path: path == preferred,
        )

        assert file_utils.get_volatility_cache_dir() == preferred


def test_get_volatility_cache_dir_uses_temp_for_frozen_build(monkeypatch):
    with _temporary_workspace() as tmp_path:
        preferred = tmp_path / "Local" / "Vol For SMEs" / "VolatilityCache"
        temp_fallback = tmp_path / "Temp" / "Vol For SMEs" / "VolatilityCache"

        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
        monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
        monkeypatch.setattr(file_utils.sys, "frozen", True, raising=False)
        monkeypatch.setattr(file_utils.tempfile, "gettempdir", lambda: str(tmp_path / "Temp"))
        monkeypatch.setattr(
            file_utils,
            "_ensure_writable_directory",
            lambda path: path == temp_fallback,
        )

        assert file_utils.get_volatility_cache_dir() == temp_fallback


def test_build_memory_image_metadata_hashes_file():
    with _temporary_workspace() as tmp_path:
        memory_image = tmp_path / "sample.mem"
        memory_image.write_bytes(b"memory-image-data")

        metadata = file_utils.build_memory_image_metadata(memory_image)

        assert metadata["path"] == str(memory_image)
        assert metadata["resolved_path"] == str(memory_image.resolve())
        assert metadata["sha256"] == (
            "39f65ddbf302ab14402515bb558aeb69c3b0e0ca492a21840ffcd87f015fa99b"
        )
        assert metadata["size_bytes"] == len(b"memory-image-data")
