"""Detect data exfiltration patterns (image/link-based, email harvesting)."""

from __future__ import annotations
import re
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from models import Finding, FindingCategory, Severity


class ExfiltrationAnalyzer(BaseAnalyzer):
    """Detect patterns used to exfiltrate data from AI agent sessions."""

    name = "exfiltration"
    description = "Detects image-based, link-based, and email-based data exfiltration patterns"

    # Patterns for exfiltration via image/link URLs
    EXFIL_URL_PATTERNS = [
        # Markdown image with dynamic parameter placeholder
        (r"!\[[^\]]*\]\([^)]*\{(?:user_?(?:data|input|message|query|response)|"
         r"secret|api_?key|token|password|credentials?|session|cookie)\}",
         "Markdown image exfiltration with variable interpolation", Severity.critical),

        # URL with obvious exfil parameter names
        (r'(?:src|href|action)\s*=\s*["\'][^"\']*[?&](?:data|exfil|steal|leak|capture|extract|collect)\s*=',
         "URL with exfiltration parameter", Severity.high),

        # Tracking pixel patterns (1x1 images loading external URLs)
        (r'<img[^>]*(?:width|height)\s*=\s*["\']?[01]["\']?[^>]*(?:width|height)\s*=\s*["\']?[01]',
         "Tracking pixel (1x1 image)", Severity.medium),

        # Dynamic URL construction patterns
        (r"(?:fetch|XMLHttpRequest|navigator\.sendBeacon|new\s+Image)\s*\([^)]*\+\s*(?:document|window|localStorage)",
         "Dynamic URL with client data exfiltration", Severity.critical),

        # Webhook/external callback patterns with data
        (r'(?:webhook|callback|notify|report|log)[^"\']*[?&](?:data|payload|body|content|msg)=',
         "Webhook with data parameter", Severity.high),
    ]

    # Email harvesting patterns
    EMAIL_PATTERNS = [
        (r"(?:send|forward|email|mailto|reply)\s*(?:to|:)\s*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
         "Email send instruction", Severity.high),
        (r"mailto:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\?(?:subject|body)=[^\"'\s]*(?:data|secret|key|token|password)",
         "Mailto link with sensitive data fields", Severity.critical),
    ]

    def analyze(self, url: str, html: str) -> list[Finding]:
        findings: list[Finding] = []
        soup = BeautifulSoup(html, "html.parser")

        # 1. Check for exfiltration URL patterns in raw HTML
        for pattern, description, severity in self.EXFIL_URL_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                findings.append(Finding(
                    category=FindingCategory.exfiltration,
                    severity=severity,
                    title=f"Exfiltration pattern: {description}",
                    description=f"Found {len(matches)} instance(s) of data exfiltration pattern.",
                    evidence=str(matches[0])[:300] if matches else "",
                    url=url,
                    analyzer=self.name,
                    recommendation="Remove data exfiltration patterns from web content.",
                ))

        # 2. Check images loading external URLs with query params
        findings.extend(self._check_image_exfil(url, soup))

        # 3. Check for email harvesting / exfiltration
        for pattern, description, severity in self.EMAIL_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                findings.append(Finding(
                    category=FindingCategory.exfiltration,
                    severity=severity,
                    title=f"Email exfiltration: {description}",
                    description=f"Found {len(matches)} instance(s) of email-based data exfiltration.",
                    evidence=str(matches[0])[:300] if matches else "",
                    url=url,
                    analyzer=self.name,
                    recommendation="Review email instructions for potential data exfiltration.",
                ))

        # 4. Check for instructions to visit external URLs
        findings.extend(self._check_external_url_instructions(url, html))

        return findings

    def _check_image_exfil(self, url: str, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        target_domain = urlparse(url).netloc

        for img in soup.find_all("img"):
            src = img.get("src", "")
            if not src:
                continue

            parsed = urlparse(src)
            # External domain image with query parameters
            if parsed.netloc and parsed.netloc != target_domain and parsed.query:
                params = parse_qs(parsed.query)
                suspicious_params = [
                    k for k in params
                    if any(s in k.lower() for s in [
                        "data", "q", "query", "input", "msg", "text",
                        "content", "payload", "user", "secret",
                    ])
                ]
                if suspicious_params:
                    findings.append(Finding(
                        category=FindingCategory.exfiltration,
                        severity=Severity.high,
                        title="External image with suspicious query parameters",
                        description=(
                            f"Image loads from external domain '{parsed.netloc}' "
                            f"with suspicious parameters: {suspicious_params}"
                        ),
                        evidence=src[:300],
                        url=url,
                        analyzer=self.name,
                        recommendation="Review external image URLs for potential data exfiltration.",
                    ))

        return findings

    def _check_external_url_instructions(self, url: str, html: str) -> list[Finding]:
        findings = []
        # Look for instructions telling the agent to visit/fetch external URLs
        patterns = [
            (r"(?:visit|navigate\s+to|go\s+to|open|fetch|load|browse\s+to)\s+(?:https?://[^\s\"'<>]+)",
             "Instruction to visit external URL", Severity.medium),
            (r"(?:click|follow)\s+(?:this|the)\s+(?:link|url)\s*:\s*(?:https?://[^\s\"'<>]+)",
             "Instruction to follow external link", Severity.medium),
            (r"(?:send|post|submit|upload)\s+(?:the|this|your)\s+(?:data|response|output|result)\s+to\s+(?:https?://[^\s\"'<>]+)",
             "Instruction to send data to external URL", Severity.critical),
        ]

        for pattern, description, severity in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                findings.append(Finding(
                    category=FindingCategory.exfiltration,
                    severity=severity,
                    title=f"Agent URL instruction: {description}",
                    description=f"Content instructs an AI agent to interact with external URLs.",
                    evidence=str(matches[0])[:300] if matches else "",
                    url=url,
                    analyzer=self.name,
                    recommendation="Remove instructions directing AI agents to external URLs.",
                ))

        return findings
