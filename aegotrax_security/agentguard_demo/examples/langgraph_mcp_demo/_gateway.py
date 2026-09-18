"""Shared helper: resolve how to launch the AgentGuard MCP Gateway."""

import os
import shutil
import sys
from pathlib import Path


def get_gateway_command() -> tuple[str, list[str]]:
    """
    Returns (command, args) for StdioServerParameters.

    Priority:
    1. `agentguard-gateway` on PATH (after pip install)
    2. Local source: agentguard_clean/agentguard/mcp_gateway.py
    3. Fallback: python -m agentguard.mcp_gateway
    """
    # 1. Installed console script
    which = shutil.which("agentguard-gateway")
    if which:
        return which, []

    # 2. Local clean package next to this demo pack
    # agentguard_demo/examples/langgraph_mcp_demo → up to artifacts
    here = Path(__file__).resolve().parent
    candidates = [
        here.parents[2] / "agentguard_clean" / "agentguard" / "mcp_gateway.py",
        here.parents[1] / "agentguard" / "mcp_gateway.py",
        Path.cwd() / "agentguard" / "mcp_gateway.py",
    ]
    for path in candidates:
        if path.exists():
            return sys.executable, [str(path)]

    # 3. Module form (works if package is on PYTHONPATH)
    return sys.executable, ["-m", "agentguard.mcp_gateway"]
