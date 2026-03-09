"""Detect hidden text injection techniques."""

from __future__ import annotations
import re
from bs4 import BeautifulSoup, Comment

from .base import BaseAnalyzer
from models import Finding, FindingCategory, Severity


class HiddenTextAnalyzer(BaseAnalyzer):
    """Detect content hidden via CSS, HTML attributes, or visual tricks."""

    name = "hidden_text"
    description = "Detects hidden text that may contain injected instructions for AI agents"

    # CSS patterns that hide content
    HIDING_CSS_PATTERNS = [
        (r"display\s*:\s*none", "display:none"),
        (r"visibility\s*:\s*hidden", "visibility:hidden"),
        (r"opacity\s*:\s*0(?:[;\s\"]|$)", "opacity:0"),
        (r"font-size\s*:\s*0", "font-size:0"),
        (r"color\s*:\s*(?:white|#fff(?:fff)?|rgb\s*\(\s*255)", "white-on-white text"),
        (r"color\s*:\s*transparent", "transparent text"),
        (r"position\s*:\s*absolute[^;]*(?:left|top)\s*:\s*-\d{4,}", "off-screen positioning"),
        (r"text-indent\s*:\s*-\d{4,}", "text-indent off-screen"),
        (r"clip\s*:\s*rect\s*\(\s*0", "clip to zero rect"),
        (r"overflow\s*:\s*hidden.*?(?:width|height)\s*:\s*0", "zero-size overflow hidden"),
        (r"height\s*:\s*0.*overflow\s*:\s*hidden", "zero height with overflow hidden"),
        (r"width\s*:\s*0.*overflow\s*:\s*hidden", "zero width with overflow hidden"),
        (r"max-height\s*:\s*0", "max-height:0"),
    ]

    # Suspicious instruction keywords that shouldn't be in hidden content
    INSTRUCTION_PATTERNS = [
        r"ignore\s+(?:previous|all|prior|above)\s+instructions",
        r"you\s+(?:are|must|should|will)\s+(?:now|always)",
        r"system\s*(?:prompt|message|instruction)",
        r"(?:do not|don't|never)\s+(?:tell|reveal|share|disclose)",
        r"(?:new|override|updated?)\s+(?:instructions?|prompt|rules?)",
        r"pretend\s+(?:you\s+are|to\s+be)",
        r"(?:act|behave)\s+as\s+(?:if|though)",
        r"(?:from now on|henceforth)",
        r"(?:disregard|forget)\s+(?:all|previous|prior|your)",
        r"<\|?\s*(?:im_start|im_end|endoftext|system|assistant)\s*\|?>",
        r"tool_use|function_call|tool_result",
    ]

    def analyze(self, url: str, html: str) -> list[Finding]:
        findings: list[Finding] = []
        soup = BeautifulSoup(html, "html.parser")

        # 1. Check HTML comments for hidden instructions
        findings.extend(self._check_comments(url, soup))

        # 2. Check inline styles for hiding techniques
        findings.extend(self._check_inline_styles(url, soup))

        # 3. Check <style> blocks
        findings.extend(self._check_style_blocks(url, soup, html))

        # 4. Check hidden inputs with suspicious values
        findings.extend(self._check_hidden_inputs(url, soup))

        # 5. Check aria-hidden, hidden attribute
        findings.extend(self._check_hidden_attributes(url, soup))

        return findings

    def _check_comments(self, url: str, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = str(comment).strip()
            if len(text) < 10:
                continue
            for pattern in self.INSTRUCTION_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(Finding(
                        category=FindingCategory.hidden_text,
                        severity=Severity.high,
                        title="Hidden instructions in HTML comment",
                        description="An HTML comment contains text that appears to be instructions targeting AI agents.",
                        evidence=text[:300],
                        url=url,
                        analyzer=self.name,
                        recommendation="Remove or sanitize HTML comments containing agent-targeted instructions.",
                    ))
                    break
        return findings

    def _check_inline_styles(self, url: str, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for el in soup.find_all(style=True):
            style = el.get("style", "")
            text = el.get_text(strip=True)
            if not text or len(text) < 5:
                continue

            for pattern, technique in self.HIDING_CSS_PATTERNS:
                if re.search(pattern, style, re.IGNORECASE):
                    # Check if the hidden content contains instructions
                    for instr_pattern in self.INSTRUCTION_PATTERNS:
                        if re.search(instr_pattern, text, re.IGNORECASE):
                            findings.append(Finding(
                                category=FindingCategory.hidden_text,
                                severity=Severity.critical,
                                title=f"Hidden instruction text via {technique}",
                                description=(
                                    f"Text hidden using CSS '{technique}' contains "
                                    "instructions that appear to target AI agents."
                                ),
                                evidence=f"Style: {style[:100]} | Text: {text[:200]}",
                                url=url,
                                analyzer=self.name,
                                recommendation="Remove hidden instruction text from the page.",
                            ))
                            break
                    else:
                        # Hidden text without obvious instructions — still suspicious
                        if len(text) > 50:
                            findings.append(Finding(
                                category=FindingCategory.hidden_text,
                                severity=Severity.medium,
                                title=f"Suspiciously hidden text via {technique}",
                                description=(
                                    f"Substantial text content hidden using CSS '{technique}'. "
                                    "May contain instructions for AI agents."
                                ),
                                evidence=f"Style: {style[:100]} | Text: {text[:200]}",
                                url=url,
                                analyzer=self.name,
                                recommendation="Review hidden text for potential prompt injection content.",
                            ))
                    break  # Don't double-count same element
        return findings

    def _check_style_blocks(self, url: str, soup: BeautifulSoup, html: str) -> list[Finding]:
        findings = []
        # Check if CSS rules target specific classes/IDs with hiding
        for style_tag in soup.find_all("style"):
            css = style_tag.string or ""
            for pattern, technique in self.HIDING_CSS_PATTERNS:
                matches = re.findall(
                    r"([.#][\w-]+)\s*\{[^}]*" + pattern + r"[^}]*\}",
                    css, re.IGNORECASE | re.DOTALL,
                )
                for selector in matches:
                    # Find elements matching this selector
                    try:
                        elements = soup.select(selector)
                        for el in elements:
                            text = el.get_text(strip=True)
                            if text and len(text) > 20:
                                for instr_pattern in self.INSTRUCTION_PATTERNS:
                                    if re.search(instr_pattern, text, re.IGNORECASE):
                                        findings.append(Finding(
                                            category=FindingCategory.hidden_text,
                                            severity=Severity.critical,
                                            title=f"CSS-hidden instructions via stylesheet ({technique})",
                                            description=(
                                                f"Element '{selector}' hidden by CSS stylesheet "
                                                f"using '{technique}' contains agent-targeted instructions."
                                            ),
                                            evidence=text[:300],
                                            url=url,
                                            analyzer=self.name,
                                            recommendation="Remove CSS-hidden instruction content.",
                                        ))
                                        break
                    except Exception:
                        pass
        return findings

    def _check_hidden_inputs(self, url: str, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for inp in soup.find_all("input", type="hidden"):
            val = inp.get("value", "")
            if len(val) < 20:
                continue
            for pattern in self.INSTRUCTION_PATTERNS:
                if re.search(pattern, val, re.IGNORECASE):
                    findings.append(Finding(
                        category=FindingCategory.hidden_text,
                        severity=Severity.high,
                        title="Hidden input contains agent instructions",
                        description="A hidden form input contains text targeting AI agents.",
                        evidence=f"name={inp.get('name', '?')} value={val[:200]}",
                        url=url,
                        analyzer=self.name,
                        recommendation="Do not store agent instructions in hidden form fields.",
                    ))
                    break
        return findings

    def _check_hidden_attributes(self, url: str, soup: BeautifulSoup) -> list[Finding]:
        findings = []
        for el in soup.find_all(attrs={"aria-hidden": "true"}):
            text = el.get_text(strip=True)
            if text and len(text) > 30:
                for pattern in self.INSTRUCTION_PATTERNS:
                    if re.search(pattern, text, re.IGNORECASE):
                        findings.append(Finding(
                            category=FindingCategory.hidden_text,
                            severity=Severity.high,
                            title="aria-hidden element contains agent instructions",
                            description="An element marked aria-hidden='true' contains AI agent instructions.",
                            evidence=text[:300],
                            url=url,
                            analyzer=self.name,
                            recommendation="Remove instruction content from aria-hidden elements.",
                        ))
                        break

        for el in soup.find_all(attrs={"hidden": True}):
            text = el.get_text(strip=True)
            if text and len(text) > 30:
                for pattern in self.INSTRUCTION_PATTERNS:
                    if re.search(pattern, text, re.IGNORECASE):
                        findings.append(Finding(
                            category=FindingCategory.hidden_text,
                            severity=Severity.high,
                            title="Hidden-attribute element contains agent instructions",
                            description="An element with HTML 'hidden' attribute contains AI agent instructions.",
                            evidence=text[:300],
                            url=url,
                            analyzer=self.name,
                            recommendation="Remove instruction content from hidden elements.",
                        ))
                        break

        return findings
