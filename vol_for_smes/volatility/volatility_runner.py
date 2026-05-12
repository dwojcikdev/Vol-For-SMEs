import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from .command_resolver import (
    build_volatility_command,
    parse_json_output,
    resolve_volatility_command,
)

class VolatilityRunner: # Wrapper for running Volatility plugins and handling their output

    def __init__(self, memory_path, volatility_path="vol", os_context=None):
        self.memory_path = memory_path
        self.os_context = os_context or {}
        self.volatility_command = list(
            self.os_context.get("volatility_command") or resolve_volatility_command(volatility_path)
        )

    def _base_args(self):
        args = ["--renderer", "json"]
        extra = self.os_context.get("volatility_args") or []
        args.extend(extra)
        args.extend(["-f", self.memory_path])
        return args

    def _format_plugin_error(self, error_text):
        message = str(error_text or "").strip()
        lowered = message.lower()

        if "file does not exist" in lowered or "requested file doesn't exist" in lowered:
            return "Volatility could not find the memory image file."
        if "invalid json" in lowered or "returned invalid json" in lowered:
            return "Volatility returned unreadable data for this plugin."
        if "was not found" in lowered:
            return "Volatility could not be started."
        if "no suitable plugins" in lowered or "unsatisfied requirement" in lowered:
            return "This plugin could not run successfully against the selected memory image."
        if "plugin failed" in lowered:
            return "This plugin could not be completed."
        if not message:
            return "This plugin could not be completed."
        return f"This plugin could not be completed. {message}"

    def run_plugin(self, plugin):
        command = build_volatility_command(
            self.volatility_command,
            self._base_args() + [plugin]
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
            print(f"[{name}] running...")
            start_time = time.time()
            try:
                result = self.run_plugin(plugin)
                end_time = time.time()
                elapsed = end_time - start_time
                minutes = int(elapsed // 60)
                seconds = elapsed % 60
                print(f"[{name}] successfully finished in {minutes}m {seconds:.2f}s")
                return name, result
            except Exception as e:
                end_time = time.time()
                elapsed = end_time - start_time
                minutes = int(elapsed // 60)
                seconds = elapsed % 60
                print(f"[{name}] failed")
                print(
                    f"[{name}] {self._format_plugin_error(str(e))} "
                    f"({minutes}m {seconds:.2f}s)"
                )
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

        overall_end = time.time()
        overall_elapsed = overall_end - overall_start
        overall_minutes = int(overall_elapsed // 60)
        overall_seconds = overall_elapsed % 60
        successful_plugins = sum(1 for result in results.values() if "error" not in result)
        total_plugins = len(plugin_dict)
        print(f"{successful_plugins} plugins out of {total_plugins} executed successfully")
        print(f"Total plugin execution time: {overall_minutes}m {overall_seconds:.2f}s")
        
        return results
