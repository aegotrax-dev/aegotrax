"""Shared helper: resolve how to launch the Aegotrax MCP Gateway."""

import os
import shutil
import sys
from pathlib import Path


def get_gateway_command() -> tuple[str, list[str]]:
    """
    Returns (command, args) for StdioServerParameters.

    Priority:
    1. `aegotrax-gateway` on PATH (after pip install)
    2. Local source checkout: <repo>/aegotrax/mcp_gateway.py
    3. Fallback: python -m aegotrax.mcp_gateway
    """
    # 1. Installed console script
    which = shutil.which("aegotrax-gateway")
    if which:
        return which, []

    # 2. Local source checkout: <repo>/examples/langgraph_mcp_demo -> <repo>
    here = Path(__file__).resolve().parent
    candidates = [
        here.parents[1] / "aegotrax" / "mcp_gateway.py",
        Path.cwd() / "aegotrax" / "mcp_gateway.py",
    ]
    for path in candidates:
        if path.exists():
            return sys.executable, [str(path)]

    # 3. Module form (works if package is on PYTHONPATH)
    return sys.executable, ["-m", "aegotrax.mcp_gateway"]
