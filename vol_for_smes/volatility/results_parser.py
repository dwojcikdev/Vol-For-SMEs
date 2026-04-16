# Cleans up and parses JSON output into structured dictionaries
from ..utils.helpers import extract_rows


def parse_processes(volatility_json):

    rows = extract_rows(volatility_json)

    processes = []

    for row in rows:
        if isinstance(row, dict):
            # Volatility 3 format: dict with column names as keys
            process = {
                "pid": row.get("PID", row.get("pid")),
                "ppid": row.get("PPID", row.get("ppid")),
                "name": row.get("ImageFileName") or row.get("name") or row.get("Name"),
                "threads": row.get("Threads", row.get("threads"))
            }
        else:
            # Legacy format: list/tuple
            process = {
                "pid": row[1] if len(row) > 1 else None,
                "ppid": row[2] if len(row) > 2 else None,
                "name": row[3] if len(row) > 3 else None,
                "threads": row[4] if len(row) > 4 else None
            }
        processes.append(process)

    return processes
