"""Detect metadata abuse and encoded payloads."""

from __future__ import annotations
import re
import base64
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from models import Finding, FindingCategory, Severity


class MetadataAnalyzer(BaseAnalyzer):
    """Detect suspicious metadata, data attributes, and encoded content."""

    name = "metadata"
    description = "Detects metadata abuse, base64 payloads, and data-attribute injection"

    # Meta tags that could carry agent instructions
    SUSPICIOUS_META_NAMES = [
        "ai-instructions", "agent-instructions", "llm-instructions",
        "bot-instructions", "assistant-instructions", "gpt-instructions",
        "claude-instructions", "system-prompt", "ai-prompt",
        "ai-agent", "chatbot-instructions",
    ]

    INSTRUCTION_KEYWORDS = [
        r"ignore\s+(?:previous|all|prior)",
        r"you\s+(?:are|must|should|will)",
        r"system\s*(?:prompt|message|instruction)",
        r"(?:new|override)\s+instructions?",
        r"pretend\s+(?:you\s+are|to\s+be)",
        r"(?:act|behave)\s+as",
        r"(?:disregard|forget)\s+(?:all|previous|prior)",
        r"tool_use|function_call|tool_result",
    ]

    def analyze(self, url: str, html: str) -> list[Finding]:
        findings: list[Finding] = []
        soup = BeautifulSoup(html, "html.parser")

        # 1. Suspicious meta tags
        findings.extend(self._check_meta_tags(url, soup))

        # 2. data-* attributes with instruction content
        findings.extend(self._check_data_attributes(url, soup))

        # 3. Base64-encoded payloads
        findings.extend(self._check_base64(url, html))

        # 4. JSON-LD / Schema.org abuse
        findings.extend(self._check_json_ld(url, soup))

        # 5. Robots meta directives targeting AI agents
        findings.extend(self._check_robots_meta(url, soup))

        return findings

    def _check_meta_tags(self, url: str, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for meta in soup.find_all("meta"):
            name = (meta.get("name") or meta.get("property") or "").lower()
            content = meta.get("content", "")

            # Check for explicitly suspicious meta names
            if any(s in name for s in self.SUSPICIOUS_META_NAMES):
                findings.append(Finding(
                    category=FindingCategory.metadata_abuse,
                    severity=Severity.high,
                    title=f"Agent-targeting meta tag: {name}",
                    description=f"Meta tag '{name}' appears designed to instruct AI agents.",
                    evidence=f"<meta name=\"{name}\" content=\"{content[:200]}\">",
                    url=url,
                    analyzer=self.name,
                    recommendation="Remove meta tags that target AI agents with instructions.",
                ))

            # Check if any meta content contains instruction patterns
            if content and len(content) > 30:
                for pattern in self.INSTRUCTION_KEYWORDS:
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append(Finding(
                            category=FindingCategory.metadata_abuse,
                            severity=Severity.high,
                            title=f"Meta tag contains agent instructions: {name}",
                            description=f"Meta tag '{name}' content contains patterns targeting AI agents.",
                            evidence=f"<meta name=\"{name}\" content=\"{content[:200]}\">",
                            url=url,
                            analyzer=self.name,
                            recommendation="Review and remove agent-targeted instructions from meta tags.",
                        ))
                        break

        return findings

    def _check_data_attributes(self, url: str, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for el in soup.find_all(True):
            for attr, val in el.attrs.items():
                if not attr.startswith("data-"):
                    continue
                if isinstance(val, list):
                    val = " ".join(val)
                if not isinstance(val, str) or len(val) < 30:
                    continue

                # Check data attributes for instruction patterns
                suspicious_attr_names = [
                    "prompt", "instruction", "system", "agent", "ai-",
                    "llm", "bot-", "assistant", "override",
                ]
                attr_lower = attr.lower()
                name_suspicious = any(s in attr_lower for s in suspicious_attr_names)

                for pattern in self.INSTRUCTION_KEYWORDS:
                    if re.search(pattern, val, re.IGNORECASE):
                        findings.append(Finding(
                            category=FindingCategory.metadata_abuse,
                            severity=Severity.high if name_suspicious else Severity.medium,
                            title=f"Data attribute contains agent instructions: {attr}",
                            description=f"HTML data attribute '{attr}' contains AI agent instruction patterns.",
                            evidence=f"{attr}=\"{val[:200]}\"",
                            url=url,
                            analyzer=self.name,
                            recommendation="Remove agent instructions from HTML data attributes.",
                        ))
                        break

        return findings

    def _check_base64(self, url: str, html: str) -> list[Finding]:
        findings = []
        # Find base64-encoded strings (minimum 40 chars to avoid false positives)
        b64_pattern = r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']'
        for match in re.finditer(b64_pattern, html):
            encoded = match.group(1)
            try:
                decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
            except Exception:
                continue

            # Check if decoded content contains instructions
            for pattern in self.INSTRUCTION_KEYWORDS:
                if re.search(pattern, decoded, re.IGNORECASE):
                    findings.append(Finding(
                        category=FindingCategory.metadata_abuse,
                        severity=Severity.critical,
                        title="Base64-encoded agent instructions detected",
                        description="A base64-encoded string decodes to text containing AI agent instructions.",
                        evidence=f"Encoded: {encoded[:80]}... -> Decoded: {decoded[:200]}",
                        url=url,
                        analyzer=self.name,
                        recommendation="Remove base64-encoded instruction payloads.",
                    ))
                    break

        return findings

    def _check_json_ld(self, url: str, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for script in soup.find_all("script", type="application/ld+json"):
            content = script.string or ""
            if len(content) < 20:
                continue

            for pattern in self.INSTRUCTION_KEYWORDS:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append(Finding(
                        category=FindingCategory.metadata_abuse,
                        severity=Severity.high,
                        title="JSON-LD contains agent instructions",
                        description="Schema.org / JSON-LD structured data contains AI agent instruction patterns.",
                        evidence=content[:300],
                        url=url,
                        analyzer=self.name,
                        recommendation="Remove agent instructions from structured data markup.",
                    ))
                    break

        return findings

    def _check_robots_meta(self, url: str, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for meta in soup.find_all("meta", attrs={"name": re.compile(r"robots?", re.I)}):
            content = (meta.get("content") or "").lower()
            # Check for AI-specific directives
            ai_directives = ["noai", "noimageai", "noagent", "noclaude", "nogpt"]
            for directive in ai_directives:
                if directive in content.replace("-", "").replace("_", ""):
                    findings.append(Finding(
                        category=FindingCategory.robots_directive,
                        severity=Severity.info,
                        title=f"AI-specific robots directive: {directive}",
                        description=f"Meta robots tag contains AI-specific directive '{directive}'.",
                        evidence=f"<meta name=\"robots\" content=\"{content}\">",
                        url=url,
                        analyzer=self.name,
                        recommendation="This is informational — the site explicitly restricts AI agent access.",
                    ))

        return findings
