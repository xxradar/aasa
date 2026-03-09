"""LLM-as-judge analyzer using Anthropic Claude API."""

from __future__ import annotations

import json
import logging
import time
from typing import Optional

import anthropic

from config import settings
from models import Finding, FindingCategory, Severity
from usage_tracker import usage
from prompts.judge_prompt import (
    JUDGE_SYSTEM_PROMPT,
    PAGE_ANALYSIS_PROMPT,
    AGENTIC_FILE_PROMPT,
    PDF_ANALYSIS_PROMPT,
    SCAN_SUMMARY_PROMPT,
)

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
}


class LLMJudgeAnalyzer:
    """Uses Claude as an LLM-as-judge to perform deep prompt injection analysis."""

    name = "llm_judge"
    description = "Agentic LLM-as-judge analysis using Claude for deep inspection"

    def __init__(self):
        self.client: Optional[anthropic.AsyncAnthropic] = None
        self._scan_id: str = ""  # Set by scanner before each analysis batch
        if settings.anthropic_api_key:
            self.client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)

    @property
    def available(self) -> bool:
        return self.client is not None and settings.llm_judge_enabled

    async def analyze_page(
        self,
        url: str,
        html: str,
        title: str = "",
        content_type: str = "",
        static_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Analyze a page using LLM-as-judge."""
        if not self.available:
            logger.warning("LLM judge not available (no API key or disabled)")
            return []

        # Format static findings for context
        findings_text = "None" if not static_findings else "\n".join(
            f"- [{f.severity.value.upper()}] {f.title}: {f.evidence[:100]}"
            for f in (static_findings or [])
        )

        # Truncate content for API limits
        content = html[:30_000]

        prompt = PAGE_ANALYSIS_PROMPT.format(
            url=url,
            title=title or "Unknown",
            content_type=content_type or "text/html",
            static_findings=findings_text,
            content_length=len(content),
            content=content,
        )

        return await self._call_judge(prompt, url, purpose="page")

    async def analyze_agentic_file(
        self,
        filename: str,
        url: str,
        content: str,
        size: int,
    ) -> list[Finding]:
        """Analyze an agentic instruction file using LLM-as-judge."""
        if not self.available:
            return []

        prompt = AGENTIC_FILE_PROMPT.format(
            filename=filename,
            url=url,
            size=size,
            content=content[:30_000],
        )

        return await self._call_judge(prompt, url, purpose="agentic_file")

    async def analyze_pdf_content(
        self,
        url: str,
        extracted: dict,
        static_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Analyze extracted PDF content using LLM-as-judge.

        Args:
            url: The URL the PDF was downloaded from.
            extracted: Dict from extract_pdf_text() with keys:
                       pages, metadata, annotations, form_fields, page_count.
            static_findings: Pre-existing findings from static analysis.
        """
        if not self.available:
            return []

        # Format visible text
        visible_text = "\n\n".join(
            f"--- Page {p['page']} ---\n{p['text']}"
            for p in extracted.get("pages", [])
            if p.get("text", "").strip()
        )[:25_000]

        # Format metadata
        meta = extracted.get("metadata", {})
        metadata_str = "\n".join(
            f"  {k}: {v}" for k, v in meta.items() if v
        ) or "  (none)"

        # Format annotations
        annots = extracted.get("annotations", [])
        annotations_str = "\n".join(
            f"  Page {a['page']}: [{a.get('type', '?')}] {a.get('content', '')[:200]}"
            for a in annots
        )[:3000] or "  (none)"

        # Format form fields
        fields = extracted.get("form_fields", [])
        fields_str = "\n".join(
            f"  Page {f['page']}: {f.get('name', '?')} = {f.get('value', '')[:200]}"
            for f in fields
        )[:3000] or "  (none)"

        # Format static findings
        findings_text = "None" if not static_findings else "\n".join(
            f"- [{f.severity.value.upper()}] {f.title}: {f.evidence[:100]}"
            for f in (static_findings or [])
        )

        prompt = PDF_ANALYSIS_PROMPT.format(
            url=url,
            page_count=extracted.get("page_count", 0),
            metadata=metadata_str,
            static_findings=findings_text,
            visible_text=visible_text,
            annotations=annotations_str,
            form_fields=fields_str,
        )

        return await self._call_judge(prompt, url, purpose="pdf")

    async def generate_summary(
        self,
        target_url: str,
        pages_crawled: int,
        agentic_files_count: int,
        all_findings: list[Finding],
    ) -> str:
        """Generate an executive summary of the full scan."""
        if not self.available:
            return "LLM judge summary unavailable (no API key configured)."

        findings_text = "\n".join(
            f"- [{f.severity.value.upper()}] [{f.category.value}] {f.title}: {f.description[:150]}"
            for f in all_findings
        )

        counts = {}
        for f in all_findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        prompt = SCAN_SUMMARY_PROMPT.format(
            target_url=target_url,
            pages_crawled=pages_crawled,
            agentic_files_count=agentic_files_count,
            total_findings=len(all_findings),
            critical_count=counts.get("critical", 0),
            high_count=counts.get("high", 0),
            medium_count=counts.get("medium", 0),
            low_count=counts.get("low", 0),
            all_findings=findings_text[:15_000],
        )

        try:
            t0 = time.monotonic()
            response = await self.client.messages.create(
                model=settings.llm_model,
                max_tokens=settings.llm_max_tokens,
                system=JUDGE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            elapsed_ms = (time.monotonic() - t0) * 1000

            u = response.usage
            usage.record(
                model=settings.llm_model,
                purpose="llm_judge:summary",
                scan_id=self._scan_id,
                input_tokens=u.input_tokens,
                output_tokens=u.output_tokens,
                duration_ms=elapsed_ms,
                cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
                cache_creation_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
            )

            return response.content[0].text
        except Exception as e:
            logger.error(f"LLM judge summary failed: {e}")
            return f"LLM judge summary failed: {e}"

    async def _call_judge(self, prompt: str, url: str, purpose: str = "judge") -> list[Finding]:
        """Make API call and parse findings from response."""
        try:
            t0 = time.monotonic()
            response = await self.client.messages.create(
                model=settings.llm_model,
                max_tokens=settings.llm_max_tokens,
                system=JUDGE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            elapsed_ms = (time.monotonic() - t0) * 1000

            # Record usage
            u = response.usage
            usage.record(
                model=settings.llm_model,
                purpose=f"llm_judge:{purpose}",
                scan_id=self._scan_id,
                input_tokens=u.input_tokens,
                output_tokens=u.output_tokens,
                duration_ms=elapsed_ms,
                cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
                cache_creation_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
            )

            text = response.content[0].text
            return self._parse_response(text, url)

        except Exception as e:
            logger.error(f"LLM judge call failed: {e}")
            return [Finding(
                category=FindingCategory.llm_judge,
                severity=Severity.info,
                title="LLM judge analysis failed",
                description=f"The LLM judge analysis could not complete: {e}",
                url=url,
                analyzer=self.name,
            )]

    def _parse_response(self, text: str, url: str) -> list[Finding]:
        """Parse LLM judge response into Finding objects."""
        findings = []

        # Extract JSON from response (may be wrapped in markdown code blocks)
        json_text = text
        try:
            if "```json" in text:
                start = text.index("```json") + 7
                end = text.index("```", start)
                json_text = text[start:end]
            elif "```" in text:
                start = text.index("```") + 3
                end = text.index("```", start)
                json_text = text[start:end]
        except ValueError:
            # Unclosed code fence — take everything after the opening fence
            if "```json" in text:
                json_text = text[text.index("```json") + 7:]
            elif "```" in text:
                json_text = text[text.index("```") + 3:]

        try:
            data = json.loads(json_text.strip())
        except json.JSONDecodeError:
            # If we can't parse JSON, create a single finding with the raw text
            findings.append(Finding(
                category=FindingCategory.llm_judge,
                severity=Severity.medium,
                title="LLM judge analysis (unstructured)",
                description=text[:1000],
                url=url,
                analyzer=self.name,
            ))
            return findings

        # Parse structured findings
        for f in data.get("findings", []):
            severity = SEVERITY_MAP.get(f.get("severity", "medium"), Severity.medium)
            findings.append(Finding(
                category=FindingCategory.llm_judge,
                severity=severity,
                title=f.get("title", "LLM judge finding"),
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                url=url,
                analyzer=self.name,
                recommendation=f.get("recommendation", ""),
            ))

        # If the overall assessment is concerning but no specific findings
        if not findings and data.get("risk_level") in ("critical", "high"):
            findings.append(Finding(
                category=FindingCategory.llm_judge,
                severity=SEVERITY_MAP.get(data["risk_level"], Severity.high),
                title=f"LLM judge: overall risk {data['risk_level']}",
                description=data.get("summary", "Elevated risk detected by LLM analysis."),
                url=url,
                analyzer=self.name,
            ))

        return findings
