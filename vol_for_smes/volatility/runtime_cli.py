"""
Bundled Volatility CLI entry point for invoking volatility3 from the current Python runtime.
"""

from __future__ import annotations

from volatility3.cli import main as run_volatility

from ..utils.app_mutex import hold_app_mutex


def main() -> int:
    hold_app_mutex()
    return int(run_volatility() or 0)

if __name__ == "__main__":
    raise SystemExit(main())
