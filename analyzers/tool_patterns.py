"""Detect tool_use, function_call, and MCP patterns in page content."""

from __future__ import annotations
import re
import json
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from models import Finding, FindingCategory, Severity


class ToolPatternAnalyzer(BaseAnalyzer):
    """Detect embedded tool invocation patterns that target AI agents."""

    name = "tool_patterns"
    description = "Detects tool_use, function_call, MCP, and API invocation patterns"

    # Patterns that mimic LLM tool calling conventions
    TOOL_CALL_PATTERNS = [
        # Anthropic-style
        (r"<tool_use>", "Anthropic tool_use XML tag", Severity.critical),
        (r"<tool_result>", "Anthropic tool_result XML tag", Severity.critical),
        (r"<function_calls?>", "function_call XML tag", Severity.critical),
        (r'"type"\s*:\s*"tool_use"', "JSON tool_use type", Severity.critical),
        (r'"type"\s*:\s*"tool_result"', "JSON tool_result type", Severity.critical),

        # OpenAI-style
        (r'"function_call"\s*:\s*\{', "OpenAI function_call JSON", Severity.critical),
        (r'"tool_calls"\s*:\s*\[', "OpenAI tool_calls JSON", Severity.critical),
        (r'"role"\s*:\s*"(?:system|assistant|function|tool)"', "Chat role injection", Severity.high),

        # MCP-style
        (r'"method"\s*:\s*"tools/call"', "MCP tools/call pattern", Severity.critical),
        (r'"method"\s*:\s*"tools/list"', "MCP tools/list pattern", Severity.high),
        (r'"jsonrpc"\s*:\s*"2\.0"', "JSON-RPC pattern (MCP)", Severity.medium),

        # Generic patterns
        (r"<\|im_start\|>", "ChatML im_start token", Severity.critical),
        (r"<\|im_end\|>", "ChatML im_end token", Severity.critical),
        (r"<\|endoftext\|>", "GPT endoftext token", Severity.high),
        (r"\[INST\]", "Llama INST token", Severity.high),
        (r"\[/INST\]", "Llama /INST token", Severity.high),
        (r"<<SYS>>", "Llama SYS token", Severity.critical),

        # Agent framework patterns
        (r'"action"\s*:\s*"[^"]*"\s*,\s*"action_input"', "ReAct/LangChain action pattern", Severity.high),
        (r"Thought:\s*.*\nAction:\s*.*\nAction Input:", "ReAct agent chain", Severity.high),
        (r'"tool_name"\s*:\s*"', "Generic tool invocation pattern", Severity.medium),
    ]

    def analyze(self, url: str, html: str) -> list[Finding]:
        findings: list[Finding] = []

        # Check raw HTML for tool patterns
        for pattern, description, severity in self.TOOL_CALL_PATTERNS:
            matches = list(re.finditer(pattern, html, re.IGNORECASE))
            if matches:
                # Get context around the match
                match = matches[0]
                start = max(0, match.start() - 50)
                end = min(len(html), match.end() + 100)
                context = html[start:end]

                findings.append(Finding(
                    category=FindingCategory.tool_pattern,
                    severity=severity,
                    title=f"Tool/API pattern detected: {description}",
                    description=(
                        f"Found {len(matches)} occurrence(s) of '{description}' pattern. "
                        "This could be used to trick AI agents into executing tool calls."
                    ),
                    evidence=context[:300],
                    url=url,
                    analyzer=self.name,
                    recommendation="Remove or sanitize embedded tool calling patterns from web content.",
                ))

        # Check for JSON blocks that look like tool calls
        findings.extend(self._check_json_tool_calls(url, html))

        return findings

    def _check_json_tool_calls(self, url: str, html: str) -> list[Finding]:
        findings = []
        soup = BeautifulSoup(html, "html.parser")

        # Check script tags for tool-like JSON
        for script in soup.find_all("script"):
            content = script.string or ""
            if not content or len(content) < 20:
                continue

            # Try to find JSON objects that look like tool calls
            json_pattern = r'\{[^{}]*"(?:tool_use|function_call|tool_calls|action|tool_name)"[^{}]*\}'
            for match in re.finditer(json_pattern, content):
                try:
                    obj = json.loads(match.group())
                    findings.append(Finding(
                        category=FindingCategory.tool_pattern,
                        severity=Severity.high,
                        title="Valid JSON tool call structure in script",
                        description="A script tag contains a valid JSON object resembling a tool call.",
                        evidence=match.group()[:300],
                        url=url,
                        analyzer=self.name,
                        recommendation="Ensure tool call JSON in scripts cannot be parsed by AI agents.",
                    ))
                except json.JSONDecodeError:
                    pass

        return findings
