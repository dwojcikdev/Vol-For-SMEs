import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from .command_resolver import (
    build_volatility_command,
    detect_volatility_variant,
    parse_json_output,
    resolve_volatility_command,
)

VOL2_PLUGIN_MAP = {
    "windows.pslist": "pslist",
    "windows.psscan": "psscan",
    "windows.dlllist": "dlllist",
    "windows.cmdline": "cmdline",
    "windows.handles": "handles",
    "windows.netscan": "netscan",
    "windows.sockets": "sockets",
    "windows.filescan": "filescan",
    "windows.malfind": "malfind",
    "windows.vadinfo": "vadinfo",
    "windows.ssdt": "ssdt",
    "windows.modules": "modules",
    "windows.shimcache": "shimcache",
    "windows.svcscan": "svcscan",
    "windows.getsids": "getsids",
}

class VolatilityRunner: # Wrapper for running Volatility plugins and handling their output

    def __init__(self, memory_path, volatility_path="vol", os_context=None):
        self.memory_path = memory_path
        self.os_context = os_context or {}
        self.volatility_command = list(
            self.os_context.get("volatility_command") or resolve_volatility_command(volatility_path)
        )
        self.volatility_variant = self.os_context.get("volatility_variant") or detect_volatility_variant(self.volatility_command)

    def _base_args(self):
        args = []
        if self.volatility_variant == "vol3":
            args.extend(["--renderer", "json"])
        else:
            args.extend(["--output=json"])

        extra = self.os_context.get("volatility_args") or []
        args.extend(extra)
        args.extend(["-f", self.memory_path])
        return args

    def _translate_plugin(self, plugin):
        if self.volatility_variant == "vol2":
            return VOL2_PLUGIN_MAP.get(plugin, plugin)
        return plugin

    def run_plugin(self, plugin):
        translated_plugin = self._translate_plugin(plugin)

        command = build_volatility_command(
            self.volatility_command,
            self._base_args() + [translated_plugin]
        )

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"Volatility command '{' '.join(self.volatility_command)}' was not found. "
                "Install Volatility 3 or provide the full executable path."
            ) from exc

        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout)

        try:
            return parse_json_output(result.stdout)
        except Exception:
            raise RuntimeError("Volatility returned invalid JSON")

    def run_multiple(self, plugins, max_workers=3):
        """
        Run multiple plugins concurrently to speed up execution.
        
        Args:
            plugins: List of plugin commands or dict of name->plugin mappings
            max_workers: Maximum number of concurrent plugin executions
        """
        if isinstance(plugins, list):
            # Convert list to dict with plugin name as key
            plugin_dict = {plugin: plugin for plugin in plugins}
        else:
            plugin_dict = plugins
            
        results = {}
        
        def run_single_plugin(name, plugin):
            translated_plugin = self._translate_plugin(plugin)
            command = build_volatility_command(
                self.volatility_command,
                self._base_args() + [translated_plugin]
            )
            print(f"Running {name}...\nCommand: {' '.join(command)}")
            start_time = time.time()
            try:
                result = self.run_plugin(plugin)
                end_time = time.time()
                elapsed = end_time - start_time
                minutes = int(elapsed // 60)
                seconds = elapsed % 60
                print(f"Completed {name} in {minutes}m {seconds:.2f}s")
                return name, result
            except Exception as e:
                end_time = time.time()
                elapsed = end_time - start_time
                minutes = int(elapsed // 60)
                seconds = elapsed % 60
                print(f"Failed {name} in {minutes}m {seconds:.2f}s: {str(e)}")
                return name, {"error": str(e)}
        
        overall_start = time.time()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all plugin runs
            future_to_name = {
                executor.submit(run_single_plugin, name, plugin): name 
                for name, plugin in plugin_dict.items()
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_name):
                name, result = future.result()
                results[name] = result
                print(f"\nOutput for {name}:")
                try:
                    print(json.dumps(result, indent=2))
                except TypeError:
                    print(str(result))
                print()
        
        overall_end = time.time()
        overall_elapsed = overall_end - overall_start
        overall_minutes = int(overall_elapsed // 60)
        overall_seconds = overall_elapsed % 60
        print(f"Total plugin execution time: {overall_minutes}m {overall_seconds:.2f}s")
        
        return results

