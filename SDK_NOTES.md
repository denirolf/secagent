# Claude Agent SDK integration notes

Pinned: `claude-agent-sdk==0.2.165` (verified against the installed package, not from memory).

## What we use (and why)
We drive agents with the **Claude Agent SDK**, exposing our security tools as
**typed in-process MCP tools** and gating every tool call through our Scope Engine.
The model only selects *which* tool and *what typed parameters*; it never composes a
shell command.

| SDK symbol | Use |
|---|---|
| `@tool(name, description, input_schema)` | Define a typed tool; handler is `async def(args: dict) -> {"content":[{"type":"text","text":...}]}` |
| `create_sdk_mcp_server(name, version, tools=[...])` | Bundle tools into an in-process MCP server |
| `ClaudeAgentOptions(...)` | mcp_servers, allowed_tools, disallowed_tools, can_use_tool, hooks, system_prompt, model, max_turns, permission_mode, cwd, env |
| `ClaudeSDKClient(options)` | async ctx mgr; `await client.query(text)`, `async for m in client.receive_response()` |
| `AssistantMessage` / `TextBlock` / `ToolUseBlock` / `ResultMessage` | parse responses & cost |
| `can_use_tool(name, input, ctx) -> PermissionResultAllow()/PermissionResultDeny(message=...)` | the authorization gate |
| `HookMatcher` + PreToolUse hook | audit logging of every attempted tool call |

## Critical gotcha (enforced in our code)
Listing a tool in `allowed_tools` **auto-approves** it and **shadows** the
`can_use_tool` callback (`CanUseToolShadowedWarning`). To force every tool call through
the Scope Engine we therefore:
- leave `allowed_tools` **empty**,
- put all built-in tools in `disallowed_tools` (`Bash`, `Read`, `Write`, `Edit`,
  `WebFetch`, `WebSearch`, `ToolSearch`, …) so the model can use nothing but our typed tools,
- enforce scope/approval in `can_use_tool`,
- re-validate + re-check scope **inside each tool handler** (defense in depth),
- log every attempt via a PreToolUse hook.

## Auth
Standalone deployment needs `ANTHROPIC_API_KEY`. Inside the Claude Code cloud session
the SDK uses the session's ambient CLI auth, so the e2e can run without a key here.
