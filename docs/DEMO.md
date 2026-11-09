# 🛡️ Aegotrax — Demo Pack

This pack lets you **see Aegotrax block attacks in real time**.

It assumes you already installed the core package:

```bash
# From the repo root
pip install .
# or
pip install ".[demo]"
```

---

## 📋 Prerequisites

1. **Python 3.10+**
2. **Aegotrax installed** (`aegotrax-engine` and `aegotrax-gateway` available in PATH)
3. **OpenAI API key** (only for the full LangGraph demo)

```bash
export OPENAI_API_KEY=your-key-here
# optional
cp .env.example .env   # if you prefer a file
```

---

## 🚀 Quick Start (3 steps)

### Terminal 1 — Start the Risk Engine

```bash
aegotrax-engine
```

You should see Uvicorn running on `http://127.0.0.1:8000`.

### Terminal 2 — Run a demo

**Option A — Direct attack test (no LLM, fastest)**

```bash
python examples/langgraph_mcp_demo/direct_attack_test.py
```

Expected: `list_users` is allowed → `http_post` to attacker is **BLOCKED**.

**Option B — Full LangGraph agent demo**

```bash
pip install "aegotrax[demo]"   # if not already
python examples/langgraph_mcp_demo/demo_agent.py
```

Expected: the agent tries to exfiltrate and Aegotrax blocks it at runtime.

**Option C — Benchmark (offline, no LLM)**

```bash
# In-process, no server needed (needs the package installed):
python benchmark/run_benchmark.py --in-process

# Or against a running engine (set AEGOTRAX_API_KEY first):
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
| `benchmark/run_benchmark.py` | Scenario benchmark — see `benchmark/README.md` |
| `examples/langgraph_mcp_demo/redteam_scenarios.json` | Sample red-team prompts |

---

## ⚙️ Useful environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `AEGOTRAX_MODE` | `simulate` | `simulate` / `echo` / `forward` |
| `AEGOTRAX_ENGINE_URL` | `http://127.0.0.1:8000/verify-multi-agent` | Risk engine endpoint |
| `AEGOTRAX_POLICY_PATH` | — | Custom `policy.yaml` |
| `OPENAI_API_KEY` | — | Required for LangGraph demo |

Example (real outbound HTTP when allowed):

```bash
AEGOTRAX_MODE=forward python examples/langgraph_mcp_demo/test_forward.py
```

---

## ✅ What success looks like

```
🚨 [Aegotrax] ACTION BLOCKED
Tool: http_post
Risk Score: 70/100
Reasons: HIGH RISK: Exfiltration of sensitive payload to untrusted destination 'http://attacker-analytics.org'.
```

If you see that — the Design Partner demo is working.
