"""Detect markdown injection and iframe injection patterns."""

from __future__ import annotations
import re
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from models import Finding, FindingCategory, Severity


class MarkdownInjectionAnalyzer(BaseAnalyzer):
    """Detect markdown injection, iframe injection, and rendering abuse."""

    name = "markdown_injection"
    description = "Detects markdown rendering abuse, iframe injection, and content injection patterns"

    def analyze(self, url: str, html: str) -> list[Finding]:
        findings: list[Finding] = []
        soup = BeautifulSoup(html, "html.parser")

        # 1. Markdown-style injection in HTML content
        findings.extend(self._check_markdown_injection(url, html))

        # 2. Iframe injection
        findings.extend(self._check_iframes(url, soup))

        # 3. SVG-based injection
        findings.extend(self._check_svg_injection(url, soup))

        # 4. Object/embed tags
        findings.extend(self._check_object_embed(url, soup))

        return findings

    def _check_markdown_injection(self, url: str, html: str) -> list[Finding]:
        findings = []

        patterns = [
            # Markdown image with external tracking
            (r"!\[[^\]]*\]\(https?://[^)]*(?:track|log|exfil|collect|webhook)[^)]*\)",
             "Markdown image with tracking URL", Severity.high),

            # Markdown link with javascript:
            (r"\[[^\]]*\]\(javascript:[^)]*\)",
             "Markdown link with javascript: URI", Severity.critical),

            # Markdown link with data: URI
            (r"\[[^\]]*\]\(data:[^)]*\)",
             "Markdown link with data: URI", Severity.high),

            # Hidden markdown text (zero-width chars)
            (r"[\u200b\u200c\u200d\u2060\ufeff]{3,}",
             "Zero-width character sequence (steganography)", Severity.medium),

            # Markdown code block with tool calls
            (r"```(?:json|yaml|xml)?\s*\n[^`]*(?:tool_use|function_call|system_prompt)[^`]*```",
             "Code block containing tool call patterns", Severity.high),

            # Invisible Unicode characters used for instruction hiding
            (r"[\u2028\u2029\u00ad\u034f\u180e]{2,}",
             "Unicode formatting characters (potential hidden text)", Severity.medium),
        ]

        for pattern, description, severity in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                findings.append(Finding(
                    category=FindingCategory.markdown_injection,
                    severity=severity,
                    title=f"Markdown injection: {description}",
                    description=f"Found {len(matches)} instance(s) of markdown injection pattern.",
                    evidence=str(matches[0])[:300] if matches else "",
                    url=url,
                    analyzer=self.name,
                    recommendation="Sanitize markdown content to prevent injection attacks.",
                ))

        return findings

    def _check_iframes(self, url: str, soup: BeautifulSoup) -> list[Finding]:
        findings = []

        for iframe in soup.find_all("iframe"):
            src = iframe.get("src", "")
            srcdoc = iframe.get("srcdoc", "")
            style = iframe.get("style", "")

            # Hidden iframes
            is_hidden = (
                "display:none" in style.replace(" ", "")
                or "visibility:hidden" in style.replace(" ", "")
                or "width:0" in style.replace(" ", "")
                or "height:0" in style.replace(" ", "")
                or iframe.get("width") in ("0", "1")
                or iframe.get("height") in ("0", "1")
                or iframe.has_attr("hidden")
            )

            if is_hidden:
                findings.append(Finding(
                    category=FindingCategory.iframe_injection,
                    severity=Severity.high,
                    title="Hidden iframe detected",
                    description=f"A hidden iframe loads content from: {src[:100] or 'srcdoc'}",
                    evidence=str(iframe)[:300],
                    url=url,
                    analyzer=self.name,
                    recommendation="Remove hidden iframes that could inject content into AI agent contexts.",
                ))

            # srcdoc with instructions
            if srcdoc:
                from .prompt_injection import PromptInjectionAnalyzer
                pi = PromptInjectionAnalyzer()
                for pattern, title, severity in pi.INJECTION_PATTERNS:
                    if re.search(pattern, srcdoc, re.IGNORECASE):
                        findings.append(Finding(
                            category=FindingCategory.iframe_injection,
                            severity=Severity.critical,
                            title=f"Iframe srcdoc contains injection: {title}",
                            description="An iframe's srcdoc attribute contains prompt injection patterns.",
                            evidence=srcdoc[:300],
                            url=url,
                            analyzer=self.name,
                            recommendation="Remove prompt injection content from iframe srcdoc.",
                        ))
                        break

            # javascript: URI in iframe
            if src.strip().lower().startswith("javascript:"):
                findings.append(Finding(
                    category=FindingCategory.iframe_injection,
                    severity=Severity.critical,
                    title="Iframe with javascript: URI",
                    description="An iframe uses a javascript: URI which could execute arbitrary code.",
                    evidence=src[:200],
                    url=url,
                    analyzer=self.name,
                    recommendation="Never use javascript: URIs in iframe src attributes.",
                ))

        return findings

    def _check_svg_injection(self, url: str, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for svg in soup.find_all("svg"):
            # Check for foreignObject (can embed HTML)
            foreign = svg.find_all("foreignObject")
            if foreign:
                for fo in foreign:
                    text = fo.get_text(strip=True)
                    if len(text) > 30:
                        findings.append(Finding(
                            category=FindingCategory.markdown_injection,
                            severity=Severity.medium,
                            title="SVG foreignObject contains text content",
                            description="An SVG foreignObject element embeds text that agents may process.",
                            evidence=text[:200],
                            url=url,
                            analyzer=self.name,
                            recommendation="Review SVG foreignObject content for injection patterns.",
                        ))

            # Script in SVG
            scripts = svg.find_all("script")
            if scripts:
                findings.append(Finding(
                    category=FindingCategory.markdown_injection,
                    severity=Severity.high,
                    title="SVG contains embedded script",
                    description="An SVG element contains a script tag.",
                    evidence=str(scripts[0])[:200],
                    url=url,
                    analyzer=self.name,
                    recommendation="Remove scripts from SVG elements.",
                ))

        return findings

    def _check_object_embed(self, url: str, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for tag_name in ("object", "embed"):
            for el in soup.find_all(tag_name):
                src = el.get("data", "") or el.get("src", "")
                style = el.get("style", "")
                is_hidden = (
                    "display:none" in style.replace(" ", "")
                    or el.get("width") in ("0", "1")
                    or el.get("height") in ("0", "1")
                )
                if is_hidden:
                    findings.append(Finding(
                        category=FindingCategory.iframe_injection,
                        severity=Severity.medium,
                        title=f"Hidden <{tag_name}> element",
                        description=f"A hidden {tag_name} tag loads: {src[:100]}",
                        evidence=str(el)[:300],
                        url=url,
                        analyzer=self.name,
                        recommendation=f"Remove hidden <{tag_name}> elements.",
                    ))
        return findings
