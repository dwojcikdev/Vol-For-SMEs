# Dictionary of common Volatility plugins with simple descriptions
# Designed for users with limited memory forensics knowledge.

PLUGINS = {
    "windows.pslist": "Show running processes remembered in memory.",
    "windows.psscan": "Find processes by scanning memory directly, even if hidden.",
    "windows.dlllist": "List loaded DLLs for each process to help spot suspicious modules.",
    "windows.cmdline": "Show the command line used to start each process.",
    "windows.handles": "List open files, registry keys, and other objects used by processes.",
    "windows.netscan": "Find network connections from memory to see active communication.",
    "windows.sockets": "List network sockets in use by programs.",
    "windows.filescan": "Scan memory for file objects, useful when files are hidden or deleted.",
    "windows.malfind": "Look for suspicious code inside processes that may indicate malware.",
    "windows.vadinfo": "Show memory regions allocated by a process to understand its memory usage.",
    "windows.ssdt": "Show system call hooks that can reveal kernel-level tampering.",
    "windows.modules": "List loaded kernel modules and drivers from memory.",
    "windows.shimcache": "Read application compatibility cache entries to see programs that ran.",
    "windows.svcscan": "List Windows services and their status from memory.",
    "windows.getsids": "Show security identifiers for processes, useful for checking account use.",
}


# Plugin groups for common investigation workflows
PLUGIN_GROUPS = {

    "process_analysis": [
        "windows.pslist",
        "windows.psscan",
        "windows.cmdline",
        "windows.dlllist"
    ],

    "network_analysis": [
        "windows.netscan",
        "windows.sockets"
    ],

    "malware_analysis": [
        "windows.malfind",
        "windows.vadinfo",
        "windows.handles"
    ],

    "system_analysis": [
        "windows.modules",
        "windows.ssdt",
        "windows.svcscan",
        "windows.getsids"
    ],

    "file_activity": [
        "windows.filescan",
        "windows.shimcache"
    ],

    # Default investigation used by Vol For SMEs
    "default_investigation": [
        "windows.pslist",
        "windows.cmdline",
        "windows.netscan",
        "windows.malfind",
        "windows.dlllist",
        "windows.handles"
    ]
}