from pathlib import Path

from vol_for_smes.utils import file_utils


def test_get_reports_dir_uses_local_app_data(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))

    assert file_utils.get_reports_dir() == (
        tmp_path / "Local" / "Vol For SMEs" / "Reports"
    )


def test_build_memory_image_metadata_hashes_file(tmp_path):
    memory_image = tmp_path / "sample.mem"
    memory_image.write_bytes(b"memory-image-data")

    metadata = file_utils.build_memory_image_metadata(memory_image)

    assert metadata["path"] == str(memory_image)
    assert metadata["resolved_path"] == str(memory_image.resolve())
    assert metadata["sha256"] == (
        "39f65ddbf302ab14402515bb558aeb69c3b0e0ca492a21840ffcd87f015fa99b"
    )
    assert metadata["size_bytes"] == len(b"memory-image-data")
