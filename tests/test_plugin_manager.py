from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vol_for_smes.volatility import plugin_manager


SAMPLE_HELP_OUTPUT = """
usage: vol.py --help

Plugins:
  For plugin specific options, run 'vol.py <plugin> --help'

  PLUGIN
    windows.pslist.PsList
                        Lists the processes present in a particular windows
                        memory image.
    windows.malfind.Malfind
                        Lists process memory ranges that potentially contain
                        injected code.
    frameworkinfo.FrameworkInfo
                        Plugin to list the various modular components of
                        Volatility
"""


def test_parse_plugin_help_output_reads_wrapped_descriptions():
    plugins = plugin_manager._parse_plugin_help_output(SAMPLE_HELP_OUTPUT)

    assert set(plugins) == {
        "windows.pslist.PsList",
        "windows.malfind.Malfind",
        "frameworkinfo.FrameworkInfo",
    }
    assert (
        plugins["windows.pslist.PsList"].description
        == "Lists the processes present in a particular windows memory image."
    )
    assert (
        plugins["frameworkinfo.FrameworkInfo"].description
        == "Plugin to list the various modular components of Volatility"
    )


@patch("vol_for_smes.volatility.plugin_manager.resolve_volatility_command", return_value=["vol"])
@patch("vol_for_smes.volatility.plugin_manager.subprocess.run")
def test_discover_volatility_plugins_normalises_curated_windows_aliases(
    mock_run,
    _mock_resolve,
):
    mock_run.return_value = SimpleNamespace(
        returncode=0,
        stdout=SAMPLE_HELP_OUTPUT,
        stderr="",
    )

    plugins = plugin_manager.discover_volatility_plugins()

    assert "windows.pslist" in plugins
    assert plugins["windows.pslist"].aliases == ("windows.pslist.PsList",)
    assert plugins["windows.pslist"].support_level == "context"
    assert plugins["windows.malfind"].aliases == ("windows.malfind.Malfind",)
    assert "frameworkinfo.FrameworkInfo" in plugins
    assert plugins["frameworkinfo.FrameworkInfo"].support_level == "runnable_only"


@patch(
    "vol_for_smes.volatility.plugin_manager.discover_volatility_plugins",
    side_effect=RuntimeError("help failed"),
)
def test_build_plugin_catalog_falls_back_to_curated_plugins(_mock_discover):
    catalog = plugin_manager.build_plugin_catalog()

    assert "windows.pslist" in catalog
    assert catalog["windows.pslist"].source == "curated"


def test_validate_plugin_names_accepts_aliases_and_deduplicates():
    catalog = {
        "windows.pslist": plugin_manager.PluginInfo(
            name="windows.pslist",
            aliases=("windows.pslist.PsList",),
        ),
        "frameworkinfo.FrameworkInfo": plugin_manager.PluginInfo(
            name="frameworkinfo.FrameworkInfo",
        ),
    }

    validated = plugin_manager.validate_plugin_names(
        [
            "windows.pslist.PsList",
            "windows.pslist",
            "frameworkinfo.FrameworkInfo",
        ],
        plugin_catalog=catalog,
    )

    assert validated == ["windows.pslist", "frameworkinfo.FrameworkInfo"]


def test_validate_plugin_names_rejects_unknown_plugins():
    with pytest.raises(ValueError, match="Unknown plugins: windows.unknown"):
        plugin_manager.validate_plugin_names(
            ["windows.unknown"],
            plugin_catalog=plugin_manager.get_curated_plugin_catalog(),
        )
