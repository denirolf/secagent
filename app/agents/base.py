"""Agent base: expose the gated security tools to the Claude Agent SDK.

Each registered security tool becomes a typed in-process MCP tool. The tool handler is
the real enforcement point: it builds a ToolRequest and runs it through the SecureExecutor
(scope -> params -> approval -> sandbox -> audit). The `can_use_tool` callback lets only
our tools reach that handler and denies everything else; all built-in tools are also
disallowed, so the model cannot run arbitrary shell or read/write files.

A deterministic runner (`run_plan_deterministic`) executes a fixed tool plan without an
LLM; it is used by tests and as a fallback when the SDK/API is unavailable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import claude_agent_sdk as sdk

from app.contracts.messages import ToolRequest
from app.engine.executor import ExecResult, ProjectContext, SecureExecutor
from app.engine.registry import ToolRegistry

_DISALLOWED_BUILTINS = [
    "Bash", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit",
    "WebFetch", "WebSearch", "ToolSearch", "Glob", "Grep", "Task", "TodoWrite",
]


@dataclass
class ToolCallRecord:
    tool_id: str
    target: str
    status: str
    summary: str
    structured: dict[str, Any] | None = None
    stdout: str = ""


@dataclass
class AgentRuntime:
    agent_id: str
    executor: SecureExecutor
    registry: ToolRegistry
    ctx: ProjectContext
    max_tool_calls: int
    records: list[ToolCallRecord] = field(default_factory=list)
    tool_calls_used: int = 0

    async def invoke(self, tool_id: str, target: str, params: dict[str, Any]) -> ExecResult:
        if self.tool_calls_used >= self.max_tool_calls:
            raise RuntimeError("tool-call budget exhausted")
        spec = self.registry.get(tool_id)
        req = ToolRequest(
            tool_id=tool_id,
            operation_class=spec.operation_class,
            target=target,
            params=params,
            requires_approval=spec.requires_approval,
        )
        res = await self.executor.execute(req, agent_id=self.agent_id, ctx=self.ctx)
        self.tool_calls_used += 1
        self.records.append(ToolCallRecord(
            tool_id=tool_id, target=target, status=res.status,
            summary=res.summary,
            structured=res.run.structured if res.run else None,
            stdout=res.run.stdout if res.run else "",
        ))
        return res


def _result_text(res: ExecResult) -> str:
    if res.status != "executed":
        return f"[{res.status}] {res.summary}"
    run = res.run
    if run and run.structured:
        import json
        return "RESULT(json): " + json.dumps(run.structured)
    if run and run.stdout:
        return "RESULT(stdout, truncated):\n" + run.stdout[:6000]
    return f"[{res.status}] {res.summary}"


def build_sdk_tools(runtime: AgentRuntime) -> list:
    tools = []
    for tool_id in runtime.registry.ids():
        spec = runtime.registry.get(tool_id)
        schema = {"target": str, **spec.input_schema}

        def _make(tid: str):
            async def handler(args: dict) -> dict:
                target = args.get("target", "")
                params = {k: v for k, v in args.items() if k != "target"}
                try:
                    res = await runtime.invoke(tid, target, params)
                except RuntimeError as exc:
                    return {"content": [{"type": "text", "text": f"[blocked] {exc}"}]}
                return {"content": [{"type": "text", "text": _result_text(res)}]}
            return handler

        tools.append(sdk.tool(tool_id, spec.description, schema)(_make(tool_id)))
    return tools


async def _gate(tool_name: str, _inp: dict, _ctx):  # can_use_tool
    # Only our security tools may reach their (enforcing) handlers; deny all else.
    if tool_name.startswith("mcp__secengine__"):
        return sdk.PermissionResultAllow()
    return sdk.PermissionResultDeny(message=f"tool '{tool_name}' is not permitted")


@dataclass
class AgentRunOutput:
    texts: list[str]
    cost_usd: float
    is_error: bool


async def run_agent_sdk(
    runtime: AgentRuntime,
    *,
    system_prompt: str,
    user_prompt: str,
    model: str | None,
    max_turns: int,
) -> AgentRunOutput:
    server = sdk.create_sdk_mcp_server("secengine", "1.0.0", tools=build_sdk_tools(runtime))
    opts = sdk.ClaudeAgentOptions(
        mcp_servers={"secengine": server},
        allowed_tools=[],  # empty => can_use_tool is consulted (never auto-approve)
        disallowed_tools=_DISALLOWED_BUILTINS,
        can_use_tool=_gate,
        system_prompt=system_prompt,
        model=model,
        max_turns=max_turns,
        permission_mode="default",
        setting_sources=[],  # do not load local settings that could shadow the gate
    )
    texts: list[str] = []
    cost = 0.0
    is_error = False
    async with sdk.ClaudeSDKClient(options=opts) as client:
        await client.query(user_prompt)
        async for msg in client.receive_response():
            if isinstance(msg, sdk.AssistantMessage):
                for block in msg.content:
                    if isinstance(block, sdk.TextBlock):
                        texts.append(block.text)
            elif isinstance(msg, sdk.ResultMessage):
                cost = float(getattr(msg, "total_cost_usd", 0.0) or 0.0)
                is_error = bool(getattr(msg, "is_error", False))
    return AgentRunOutput(texts=texts, cost_usd=cost, is_error=is_error)


async def run_plan_deterministic(
    runtime: AgentRuntime, plan: list[tuple[str, str, dict]]
) -> None:
    """Execute a fixed [(tool_id, target, params)] plan through the gated executor."""
    for tool_id, target, params in plan:
        if runtime.tool_calls_used >= runtime.max_tool_calls:
            break
        await runtime.invoke(tool_id, target, params)
