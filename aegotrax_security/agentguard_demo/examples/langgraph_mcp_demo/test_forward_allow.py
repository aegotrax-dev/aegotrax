"""
Benign http_post with no prior sensitive access — should ALLOW + real request.

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

            print("Calling http_post to httpbin (NO sensitive access before)...")
            r = await session.call_tool(
                "http_post",
                {"url": "https://httpbin.org/post", "data": "hello-from-agentguard"},
            )
            print(r.content)


if __name__ == "__main__":
    asyncio.run(main())
