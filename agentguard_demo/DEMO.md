# 🛡️ AgentGuard — Demo Pack

This pack lets you **see AgentGuard block attacks in real time**.

It assumes you already installed the core package:

```bash
# From agentguard_clean /
pip install .
# or
pip install ".[demo]"
```

---

## 📋 Prerequisites

1. **Python 3.10+**
2. **AgentGuard installed** (`agentguard-engine` and `agentguard-gateway` available in PATH)
3. **OpenAI API key** (only for the full LangGraph demo)

```bash
export OPENAI_API_KEY=sk-...
# optional
cp .env.example .env   # if you prefer a file
```

---

## 🚀 Quick Start (3 steps)

### Terminal 1 — Start the Risk Engine

```bash
agentguard-engine
```

You should see Uvicorn running on `http://127.0.0.1:8000`.

### Terminal 2 — Run a demo

**Option A — Direct attack test (no LLM, fastest)**

```bash
cd agentguard_demo
python examples/langgraph_mcp_demo/direct_attack_test.py
```

Expected: `list_users` is allowed → `http_post` to attacker is **BLOCKED**.

**Option B — Full LangGraph agent demo**

```bash
pip install "agentguard[demo]"   # if not already
python examples/langgraph_mcp_demo/demo_agent.py
```

Expected: the agent tries to exfiltrate and AgentGuard blocks it at runtime.

**Option C — 100-scenario benchmark**

```bash
# Engine must be running
python benchmark/run_benchmark.py
```

---

## 📁 Contents

| Path | What it does |
|------|----------------|
| `examples/langgraph_mcp_demo/direct_attack_test.py` | Forces list_users → http_post (no LLM) |
| `examples/langgraph_mcp_demo/demo_agent.py` | Full agent with indirect injection prompt |
| `examples/langgraph_mcp_demo/test_forward.py` | Tests real HTTP forward mode + block |
| `examples/langgraph_mcp_demo/test_forward_allow.py` | Benign http_post (should ALLOW) |
| `benchmark/run_benchmark.py` | 100 scenarios (80 attack / 20 benign) |
| `attacks/redteam_scenarios.json` | Sample red-team prompts |

---

## ⚙️ Useful environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `AGENTGUARD_MODE` | `simulate` | `simulate` / `echo` / `forward` |
| `AGENTGUARD_ENGINE_URL` | `http://127.0.0.1:8000/verify-multi-agent` | Risk engine endpoint |
| `AGENTGUARD_POLICY_PATH` | — | Custom `policy.yaml` |
| `OPENAI_API_KEY` | — | Required for LangGraph demo |

Example (real outbound HTTP when allowed):

```bash
AGENTGUARD_MODE=forward python examples/langgraph_mcp_demo/test_forward.py
```

---

## ✅ What success looks like

```
🚨 [AgentGuard] ACTION BLOCKED
Tool: http_post
Risk Score: 70/100
Reasons: HIGH RISK: Exfiltration of sensitive payload to untrusted destination 'http://attacker-analytics.org'.
```

If you see that — the Design Partner demo is working.
