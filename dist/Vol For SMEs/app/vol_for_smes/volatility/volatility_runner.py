import subprocess
import time
from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed
from threading import Event, Lock

from .command_resolver import (
    build_volatility_command,
    parse_json_output,
    resolve_volatility_command,
)
from ..utils.helpers import run_subprocess
from ..utils.file_utils import get_volatility_cache_dir


class VolatilityRunCancelled(RuntimeError):
    """Raised when an investigation is intentionally cancelled."""


class VolatilityRunner:  # Wrapper for running Volatility plugins and handling their output
    HIGH_COST_PLUGINS = {
        "windows.filescan",
        "windows.shimcache",
    }

    def __init__(self, memory_path, volatility_path="vol", os_context=None):
        self.memory_path = memory_path
        self.os_context = os_context or {}
        self.volatility_command = list(
            self.os_context.get("volatility_command") or resolve_volatility_command(volatility_path)
        )
        self._cancel_requested = Event()
        self._process_lock = Lock()
        self._active_processes = set()
        self._status_lock = Lock()
        self._raw_output_lock = Lock()
        self.latest_raw_outputs = {}
        self.latest_plugin_execution_log = []
        self.latest_execution_elapsed_seconds = 0.0

    def _base_args(self):
        args = []
        extra = list(self.os_context.get("volatility_args") or [])
        if "--cache-path" not in extra:
            args.extend(["--cache-path", str(get_volatility_cache_dir())])
        args.extend(["--renderer", "json"])
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

    def _store_raw_output(self, plugin_key, raw_output):
        if not plugin_key or raw_output is None:
            return
        with self._raw_output_lock:
            self.latest_raw_outputs[str(plugin_key)] = dict(raw_output)

    def _get_raw_output(self, plugin_key):
        if not plugin_key:
            return None
        with self._raw_output_lock:
            raw_output = self.latest_raw_outputs.get(str(plugin_key))
            return dict(raw_output) if isinstance(raw_output, dict) else None

    def run_plugin(self, plugin):
        command = build_volatility_command(
            self.volatility_command,
            self._base_args() + [plugin]
        )

        try:
            result = run_subprocess(
                command,
                cancel_event=self._cancel_requested,
                on_process_start=self._register_process,
                on_process_end=self._unregister_process,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"Volatility command '{' '.join(self.volatility_command)}' was not found. "
                "Install Volatility 3 or provide the full executable path."
            ) from exc
        except InterruptedError as exc:
            raise VolatilityRunCancelled("Investigation was cancelled.") from exc

        if self._cancel_requested.is_set():
            raise VolatilityRunCancelled("Investigation was cancelled.")

        raw_output = {
            "command": list(command),
            "returncode": int(result.returncode),
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
        }
        self._store_raw_output(plugin, raw_output)

        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout)

        try:
            return parse_json_output(result.stdout)
        except Exception:
            raise RuntimeError("Volatility returned invalid JSON")

    @staticmethod
    def _format_elapsed(elapsed_seconds):
        total_seconds = max(float(elapsed_seconds or 0.0), 0.0)
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours >= 1:
            return f"{int(hours):02d}h {int(minutes):02d}m {seconds:05.2f}s"
        return f"{int(minutes):02d}m {seconds:05.2f}s"

    @classmethod
    def _format_timeline_offset(cls, elapsed_seconds):
        return cls._format_elapsed(elapsed_seconds)

    @staticmethod
    def _progress_bar(completed, total, width=20):
        if total <= 0:
            return "[" + ("-" * width) + "]"
        filled = min(width, int((completed / total) * width))
        return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"

    def _progress_prefix(self, completed, total):
        return f"{self._progress_bar(completed, total)} ({completed}/{total})"

    def _emit_status(self, message):
        with self._status_lock:
            print(message, flush=True)

    @staticmethod
    def _emit_progress(progress_callback, **payload):
        if progress_callback is not None:
            progress_callback(payload)

    def _register_process(self, process: subprocess.Popen) -> None:
        with self._process_lock:
            self._active_processes.add(process)

    def _unregister_process(self, process: subprocess.Popen) -> None:
        with self._process_lock:
            self._active_processes.discard(process)

    def cancel(self):
        self._cancel_requested.set()
        with self._process_lock:
            active_processes = list(self._active_processes)
        for process in active_processes:
            try:
                process.terminate()
            except Exception:
                continue

    def run_multiple(self, plugins, max_workers=3, progress_callback=None):
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

        if self._cancel_requested.is_set():
            raise VolatilityRunCancelled("Investigation was cancelled.")

        results = {}
        with self._raw_output_lock:
            self.latest_raw_outputs = {}
        self.latest_plugin_execution_log = []
        self.latest_execution_elapsed_seconds = 0.0
        total_plugins = len(plugin_dict)
        plugin_commands = [str(plugin) for plugin in plugin_dict.values()]
        if any(plugin in self.HIGH_COST_PLUGINS for plugin in plugin_commands):
            max_workers = 1
        completed_plugins = 0
        running_plugins = []
        progress_lock = Lock()
        cancellation_error = None
        overall_start = time.perf_counter()

        self._emit_progress(
            progress_callback,
            state="pending",
            plugin=None,
            completed=0,
            total=total_plugins,
            running_plugins=[],
        )

        def run_single_plugin(name, plugin):
            if self._cancel_requested.is_set():
                raise VolatilityRunCancelled("Investigation was cancelled.")
            with progress_lock:
                current_completed = completed_plugins
                if name not in running_plugins:
                    running_plugins.append(name)
                current_running = list(running_plugins)
            start_time = time.perf_counter()
            start_offset = start_time - overall_start

            self._emit_status(
                f"{self._progress_prefix(current_completed, total_plugins)} "
                f"[{name}] running at {self._format_timeline_offset(start_offset)}..."
            )
            self._emit_progress(
                progress_callback,
                state="running",
                plugin=name,
                completed=current_completed,
                total=total_plugins,
                started_offset_seconds=start_offset,
                running_plugins=current_running,
            )
            try:
                result = self.run_plugin(plugin)
                end_time = time.perf_counter()
                elapsed = end_time - start_time
                return {
                    "name": name,
                    "plugin_key": str(plugin),
                    "result": result,
                    "success": True,
                    "elapsed": elapsed,
                    "started_offset": start_offset,
                    "finished_offset": end_time - overall_start,
                    "error_message": None,
                }
            except VolatilityRunCancelled:
                raise
            except Exception as e:
                end_time = time.perf_counter()
                elapsed = end_time - start_time
                return {
                    "name": name,
                    "plugin_key": str(plugin),
                    "result": {"error": str(e)},
                    "success": False,
                    "elapsed": elapsed,
                    "started_offset": start_offset,
                    "finished_offset": end_time - overall_start,
                    "error_message": self._format_plugin_error(str(e)),
                }

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all plugin runs
            future_to_name = {
                executor.submit(run_single_plugin, name, plugin): name
                for name, plugin in plugin_dict.items()
            }

            # Collect results as they complete
            for future in as_completed(future_to_name):
                try:
                    plugin_result = future.result()
                except CancelledError:
                    continue
                except VolatilityRunCancelled as exc:
                    cancellation_error = exc
                    name = future_to_name[future]
                    with progress_lock:
                        if name in running_plugins:
                            running_plugins.remove(name)
                    for pending_future in future_to_name:
                        if pending_future is not future:
                            pending_future.cancel()
                    continue

                name = plugin_result["name"]
                plugin_key = plugin_result["plugin_key"]
                result = plugin_result["result"]
                success = plugin_result["success"]
                elapsed = plugin_result["elapsed"]
                started_offset = plugin_result["started_offset"]
                finished_offset = plugin_result["finished_offset"]
                error_message = plugin_result["error_message"]
                results[name] = result
                raw_output = self._get_raw_output(plugin_key)
                if raw_output is not None:
                    self._store_raw_output(name, raw_output)

                with progress_lock:
                    if name in running_plugins:
                        running_plugins.remove(name)
                    completed_plugins += 1
                    current_completed = completed_plugins
                    current_running = list(running_plugins)

                prefix = self._progress_prefix(current_completed, total_plugins)
                elapsed_text = self._format_elapsed(elapsed)
                finished_text = self._format_timeline_offset(finished_offset)
                if success:
                    self._emit_status(
                        f"{prefix} [{name}] successfully finished at {finished_text} "
                        f"(plugin runtime {elapsed_text})"
                    )
                    self.latest_plugin_execution_log.append(
                        {
                            "plugin": name,
                            "plugin_key": plugin_key,
                            "status": "completed",
                            "success": True,
                            "started_offset_seconds": started_offset,
                            "finished_offset_seconds": finished_offset,
                            "elapsed_seconds": elapsed,
                            "error_message": None,
                        }
                    )
                    self._emit_progress(
                        progress_callback,
                        state="completed",
                        plugin=name,
                        completed=current_completed,
                        total=total_plugins,
                        success=True,
                        started_offset_seconds=started_offset,
                        finished_offset_seconds=finished_offset,
                        elapsed_seconds=elapsed,
                        running_plugins=current_running,
                    )
                else:
                    self._emit_status(
                        f"{prefix} [{name}] failed at {finished_text} "
                        f"(plugin runtime {elapsed_text})"
                    )
                    self._emit_status(
                        f"{prefix} [{name}] {error_message}"
                    )
                    self.latest_plugin_execution_log.append(
                        {
                            "plugin": name,
                            "plugin_key": plugin_key,
                            "status": "failed",
                            "success": False,
                            "started_offset_seconds": started_offset,
                            "finished_offset_seconds": finished_offset,
                            "elapsed_seconds": elapsed,
                            "error_message": error_message,
                        }
                    )
                    self._emit_progress(
                        progress_callback,
                        state="failed",
                        plugin=name,
                        completed=current_completed,
                        total=total_plugins,
                        success=False,
                        started_offset_seconds=started_offset,
                        finished_offset_seconds=finished_offset,
                        elapsed_seconds=elapsed,
                        error_message=error_message,
                        running_plugins=current_running,
                    )

        if cancellation_error is not None:
            raise cancellation_error

        overall_elapsed = time.perf_counter() - overall_start
        self.latest_execution_elapsed_seconds = overall_elapsed
        self.latest_plugin_execution_log.sort(
            key=lambda item: (
                float(item.get("started_offset_seconds") or 0.0),
                float(item.get("finished_offset_seconds") or 0.0),
                str(item.get("plugin") or ""),
            )
        )
        successful_plugins = sum(1 for result in results.values() if "error" not in result)
        self._emit_status(
            f"{self._progress_prefix(total_plugins, total_plugins)} "
            f"{successful_plugins} plugins out of {total_plugins} executed successfully"
        )
        self._emit_status(
            f"Total plugin execution time: {self._format_elapsed(overall_elapsed)}"
        )
        self._emit_progress(
            progress_callback,
            state="finished",
            plugin=None,
            completed=total_plugins,
            total=total_plugins,
            successful=successful_plugins,
            finished_offset_seconds=overall_elapsed,
            elapsed_seconds=overall_elapsed,
            running_plugins=[],
        )

        return results
