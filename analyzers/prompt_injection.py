"""Core prompt injection pattern detection."""

from __future__ import annotations
import re
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from models import Finding, FindingCategory, Severity


class PromptInjectionAnalyzer(BaseAnalyzer):
    """Detect direct and indirect prompt injection patterns."""

    name = "prompt_injection"
    description = "Detects prompt injection patterns targeting AI agents"

    # Categorized injection patterns with severity
    INJECTION_PATTERNS = [
        # === CRITICAL: Direct instruction override ===
        (r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|directions?)",
         "Instruction override attempt", Severity.critical),
        (r"(?:disregard|forget|abandon|drop)\s+(?:all\s+)?(?:previous|prior|earlier|your)\s+(?:instructions?|prompts?|rules?|context)",
         "Instruction discard attempt", Severity.critical),
        (r"(?:new|updated?|revised|replacement)\s+(?:system\s+)?(?:instructions?|prompt|rules?|directives?)\s*[:=]",
         "Instruction replacement", Severity.critical),
        (r"you\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\s+",
         "Identity override", Severity.critical),
        (r"(?:your|the)\s+(?:new|real|actual|true)\s+(?:purpose|role|identity|name)\s+is",
         "Identity reassignment", Severity.critical),

        # === HIGH: System prompt manipulation ===
        (r"(?:reveal|show|display|output|print|leak)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?)",
         "System prompt extraction", Severity.high),
        (r"(?:what|tell\s+me)\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions?|rules?)",
         "System prompt query", Severity.high),
        (r"(?:repeat|echo|recite)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|text)\s+(?:above|verbatim|exactly)",
         "System prompt echo request", Severity.high),

        # === HIGH: Role manipulation ===
        (r"pretend\s+(?:you\s+are|to\s+be|you're)\s+",
         "Role pretend injection", Severity.high),
        (r"(?:act|behave|respond|operate)\s+as\s+(?:if\s+you\s+(?:are|were)|though\s+you|a|an)\s+",
         "Role assumption injection", Severity.high),
        (r"(?:from\s+now\s+on|henceforth|going\s+forward|starting\s+now)\s*,?\s*you\s+(?:will|must|should|are)",
         "Persistent behavior change", Severity.high),
        (r"(?:enter|switch\s+to|activate)\s+(?:developer|debug|admin|god|sudo|unrestricted|jailbreak)\s+mode",
         "Mode switch attempt", Severity.high),

        # === HIGH: Output manipulation ===
        (r"(?:do\s+not|don't|never|must\s+not)\s+(?:tell|inform|warn|alert|reveal|mention|disclose)\s+(?:the\s+user|anyone|them)",
         "Output suppression directive", Severity.high),
        (r"(?:hide|conceal|mask|obfuscate)\s+(?:this|your|the)\s+(?:response|output|action|instruction)",
         "Response concealment", Severity.high),

        # === MEDIUM: Boundary confusion ===
        (r"</?(?:system|user|assistant|human|ai)(?:\s[^>]*)?>",
         "Chat role boundary tag", Severity.medium),
        (r"={3,}\s*(?:SYSTEM|END\s+OF\s+SYSTEM|BEGIN\s+USER|NEW\s+CONTEXT)\s*={3,}",
         "Boundary marker injection", Severity.medium),
        (r"-{3,}\s*(?:SYSTEM|INSTRUCTIONS?|CONTEXT|PROMPT)\s*-{3,}",
         "Section boundary injection", Severity.medium),

        # === MEDIUM: Behavioral manipulation ===
        (r"(?:always|must|never)\s+(?:respond|reply|answer|output)\s+(?:with|in|using)\s+",
         "Output format override", Severity.medium),
        (r"(?:whenever|every\s+time|each\s+time)\s+(?:the\s+user|someone|anyone)\s+(?:asks?|says?|mentions?)",
         "Conditional behavior injection", Severity.medium),

        # === LOW: Suspicious but may be benign ===
        (r"(?:as\s+an?\s+AI|as\s+a\s+(?:language\s+)?model)\s*,?\s+you\s+(?:should|must|can|will)",
         "AI identity framing", Severity.low),
        (r"(?:step\s+\d+|first|then|next|finally)\s*[:.]?\s*(?:ignore|override|bypass|circumvent)",
         "Multi-step injection", Severity.medium),
    ]

    def analyze(self, url: str, html: str) -> list[Finding]:
        findings: list[Finding] = []
        soup = BeautifulSoup(html, "html.parser")

        # Get visible text
        text = soup.get_text(separator="\n")

        # Also check raw HTML (some injections are in attributes)
        sources = [
            ("visible text", text),
            ("raw HTML", html),
        ]

        seen_titles = set()
        for source_name, content in sources:
            for pattern, title, severity in self.INJECTION_PATTERNS:
                if title in seen_titles:
                    continue
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    seen_titles.add(title)
                    match = matches[0]
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 80)
                    context = content[start:end].strip()

                    findings.append(Finding(
                        category=FindingCategory.prompt_injection,
                        severity=severity,
                        title=f"Prompt injection: {title}",
                        description=(
                            f"Detected {len(matches)} instance(s) of '{title}' pattern "
                            f"in {source_name}. This is a known prompt injection technique."
                        ),
                        evidence=context[:300],
                        url=url,
                        analyzer=self.name,
                        recommendation=f"Remove or sanitize content matching prompt injection pattern: {title}.",
                    ))

        return findings

    def analyze_text(self, url: str, text: str) -> list[Finding]:
        """Analyze plain text (e.g., agentic files) for injection patterns."""
        findings = []
        for pattern, title, severity in self.INJECTION_PATTERNS:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                match = matches[0]
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 80)
                context = text[start:end].strip()

                findings.append(Finding(
                    category=FindingCategory.prompt_injection,
                    severity=severity,
                    title=f"Prompt injection in agentic file: {title}",
                    description=(
                        f"Detected {len(matches)} instance(s) of '{title}' pattern "
                        "in agentic instruction file."
                    ),
                    evidence=context[:300],
                    url=url,
                    analyzer=self.name,
                    recommendation=f"Review agentic file for prompt injection: {title}.",
                ))

        return findings
