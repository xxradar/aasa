"""Core scan orchestrator — ties crawler, analyzers, and LLM judge together."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from config import settings
from models import (
    ScanRequest, ScanResult, ScanSummary, CrawledPage, Finding, Severity,
)
from crawler import Crawler, AgenticSignalScanner
from analyzers import ALL_STATIC_ANALYZERS, PDFAnalyzer, LLMJudgeAnalyzer, LearnedRuleAnalyzer

logger = logging.getLogger(__name__)

RESULTS_DIR = Path(os.environ.get("AASA_RESULTS_DIR", "/app/results"))


class Scanner:
    """Orchestrates a full attack surface scan."""

    def __init__(self):
        self.static_analyzers = [cls() for cls in ALL_STATIC_ANALYZERS]
        # Learned rules analyzer loads active rules from persistent file
        rules_file = Path(settings.rules_dir) / "learned_rules.json"
        self.learned_rule_analyzer = LearnedRuleAnalyzer(rules_file=rules_file)
        self.static_analyzers.append(self.learned_rule_analyzer)
        self.pdf_analyzer = PDFAnalyzer()
        self.llm_judge = LLMJudgeAnalyzer()

    async def scan(
        self, request: ScanRequest, result: ScanResult | None = None,
    ) -> ScanResult:
        """Run a full scan against the target URL.

        Args:
            request: Scan configuration.
            result: Optional pre-created ScanResult for live status tracking.
                    If provided, status updates are written to this object
                    in-place so callers (e.g. the polling API) can observe
                    progress in real-time.
        """
        scan_id = result.scan_id if result else str(uuid.uuid4())[:8]
        if result is None:
            result = ScanResult(
                scan_id=scan_id,
                target_url=request.url,
                started_at=datetime.now(timezone.utc),
            )
        self.llm_judge._scan_id = scan_id
        result.status = "crawling"

        logger.info(f"[{scan_id}] Starting scan of {request.url}")

        # ── Phase 1: Crawl ────────────────────────────────────────────
        crawler = Crawler(
            base_url=request.url,
            max_depth=request.max_depth,
            max_pages=request.max_pages,
        )
        agentic_scanner = AgenticSignalScanner(request.url)

        # Run crawl and agentic file scan concurrently
        pages, agentic_files = await asyncio.gather(
            crawler.crawl(),
            agentic_scanner.scan(),
        )

        result.pages = pages
        result.agentic_files = agentic_files
        result.status = "analyzing"

        logger.info(
            f"[{scan_id}] Crawled {len(pages)} pages, "
            f"found {len(agentic_files)} agentic files, "
            f"{len(crawler.pdf_contents)} PDFs"
        )

        # ── Phase 2: Static Analysis ──────────────────────────────────
        # NOTE: Static analyzers are CPU-bound (regex + BS4). We run them
        # in a thread so they don't block the asyncio event loop, keeping
        # the API responsive for other requests (polling, history, etc.).
        all_findings: list[Finding] = await asyncio.to_thread(
            self._run_static_analysis, scan_id, pages, agentic_files,
            crawler.page_contents, crawler.pdf_contents,
        )

        # ── Phase 3: LLM Judge (optional) ─────────────────────────────
        if request.enable_llm_judge and not request.static_only and self.llm_judge.available:
            result.status = "llm_analysis"
            logger.info(f"[{scan_id}] Running LLM judge analysis...")

            # Analyze top pages with most findings + all agentic files
            pages_to_judge = sorted(
                [p for p in pages if crawler.page_contents.get(p.url)],
                key=lambda p: len(p.findings),
                reverse=True,
            )[:5]  # Top 5 pages

            for page in pages_to_judge:
                html = crawler.page_contents.get(page.url, "")
                try:
                    llm_findings = await self.llm_judge.analyze_page(
                        url=page.url,
                        html=html,
                        title=page.title,
                        content_type=page.content_type,
                        static_findings=page.findings,
                    )
                    page.findings.extend(llm_findings)
                    all_findings.extend(llm_findings)
                except Exception as e:
                    logger.error(f"LLM judge failed on {page.url}: {e}")

            for af in agentic_files:
                try:
                    llm_findings = await self.llm_judge.analyze_agentic_file(
                        filename=af.filename,
                        url=af.url,
                        content=af.content,
                        size=af.size,
                    )
                    af.findings.extend(llm_findings)
                    all_findings.extend(llm_findings)
                except Exception as e:
                    logger.error(f"LLM judge failed on {af.url}: {e}")

            # Generate executive summary
            try:
                result.llm_judge_analysis = await self.llm_judge.generate_summary(
                    target_url=request.url,
                    pages_crawled=len(pages),
                    agentic_files_count=len(agentic_files),
                    all_findings=all_findings,
                )
            except Exception as e:
                logger.error(f"LLM judge summary failed: {e}")

        # ── Phase 3.5: Rule Learning ────────────────────────────────────
        llm_only = [f for f in all_findings if f.analyzer == "llm_judge"]
        if llm_only and settings.rule_learning_enabled:
            result.status = "learning_rules"
            await self._extract_rules_from_findings(scan_id, llm_only)

        # ── Phase 4: Compile Results ──────────────────────────────────
        deduped = self._dedup_findings(all_findings)
        logger.info(
            f"[{scan_id}] Dedup: {len(all_findings)} → {len(deduped)} findings "
            f"({len(all_findings) - len(deduped)} duplicates removed)"
        )
        result.findings = deduped
        result.summary = self._compute_summary(deduped, agentic_files, len(pages))
        result.completed_at = datetime.now(timezone.utc)
        result.status = "completed"

        # Confirm any learned-rule matches for validation tracking
        self._confirm_learned_rule_matches(scan_id, deduped)

        # Reload learned rules so newly promoted rules take effect next scan
        self.learned_rule_analyzer.reload()

        logger.info(
            f"[{scan_id}] Scan complete — "
            f"Risk score: {result.summary.risk_score:.1f}/100, "
            f"{result.summary.total_findings} findings"
        )

        # ── Phase 5: Persist results to disk ──────────────────────────
        self._save_results(result)

        return result

    async def scan_pdf_url(
        self,
        url: str,
        enable_llm_judge: bool = False,
        result: ScanResult | None = None,
    ) -> ScanResult:
        """Scan a single PDF URL directly (no crawling).

        Args:
            url: Direct URL to a PDF file.
            enable_llm_judge: If True, run LLM-as-judge analysis on extracted text.
            result: Optional pre-created ScanResult for live status tracking.
        """
        import httpx
        from analyzers.pdf_analyzer import extract_pdf_text

        scan_id = result.scan_id if result else str(uuid.uuid4())[:8]
        if result is None:
            result = ScanResult(
                scan_id=scan_id,
                target_url=url,
                started_at=datetime.now(timezone.utc),
            )
        self.llm_judge._scan_id = scan_id
        result.status = "downloading_pdf"

        logger.info(f"[{scan_id}] PDF scan: downloading {url}")

        # Download PDF
        try:
            async with httpx.AsyncClient(
                timeout=30, follow_redirects=True, verify=False,
                headers={"User-Agent": settings.user_agent},
            ) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    result.status = f"failed: HTTP {resp.status_code}"
                    return result
                pdf_bytes = resp.content
        except Exception as e:
            result.status = f"failed: {e}"
            return result

        result.status = "analyzing_pdf"
        page = CrawledPage(
            url=url,
            status_code=200,
            content_type="application/pdf",
            title=f"[PDF] {url.split('/')[-1]}",
            depth=0,
        )

        # ── Phase 1: Static PDF analysis (CPU-bound → thread) ────────
        raw_findings = await asyncio.to_thread(
            self.pdf_analyzer.analyze_pdf, url, pdf_bytes
        )
        all_findings = list(raw_findings)

        logger.info(f"[{scan_id}] Static PDF analysis: {len(raw_findings)} findings")

        # ── Phase 2: LLM Judge on extracted text (optional) ──────────
        if enable_llm_judge and self.llm_judge.available:
            result.status = "llm_analysis"
            logger.info(f"[{scan_id}] Running LLM judge on PDF text...")

            # Extract text for LLM
            extracted = extract_pdf_text(pdf_bytes)

            try:
                llm_findings = await self.llm_judge.analyze_pdf_content(
                    url=url,
                    extracted=extracted,
                    static_findings=raw_findings,
                )
                all_findings.extend(llm_findings)
                logger.info(f"[{scan_id}] LLM judge: {len(llm_findings)} findings")
            except Exception as e:
                logger.error(f"[{scan_id}] LLM judge failed on PDF: {e}")

            # Generate summary
            try:
                result.llm_judge_analysis = await self.llm_judge.generate_summary(
                    target_url=url,
                    pages_crawled=1,
                    agentic_files_count=0,
                    all_findings=all_findings,
                )
            except Exception as e:
                logger.error(f"[{scan_id}] LLM judge summary failed: {e}")

        # ── Phase 2.5: Rule Learning ─────────────────────────────────
        llm_only = [f for f in all_findings if f.analyzer == "llm_judge"]
        if llm_only and settings.rule_learning_enabled:
            result.status = "learning_rules"
            await self._extract_rules_from_findings(scan_id, llm_only)

        # ── Phase 3: Dedup + compile ─────────────────────────────────
        findings = self._dedup_findings(all_findings)
        logger.info(
            f"[{scan_id}] PDF dedup: {len(all_findings)} → {len(findings)} "
            f"({len(all_findings) - len(findings)} duplicates removed)"
        )
        page.findings = findings
        result.pages = [page]
        result.findings = findings
        result.summary = self._compute_summary(findings, [], 1)

        # Confirm any learned-rule matches
        self._confirm_learned_rule_matches(scan_id, findings)
        self.learned_rule_analyzer.reload()

        result.completed_at = datetime.now(timezone.utc)
        result.status = "completed"

        logger.info(
            f"[{scan_id}] PDF scan complete — "
            f"Risk score: {result.summary.risk_score:.1f}/100, "
            f"{result.summary.total_findings} findings"
        )

        self._save_results(result)
        return result

    def _run_static_analysis(
        self,
        scan_id: str,
        pages: list[CrawledPage],
        agentic_files: list,
        page_contents: dict[str, str],
        pdf_contents: dict[str, bytes],
    ) -> list[Finding]:
        """Run all static analyzers (CPU-bound, called via asyncio.to_thread).

        This method is intentionally synchronous so it can be offloaded to a
        thread pool, preventing it from blocking the async event loop.
        """
        all_findings: list[Finding] = []

        # Analyze each crawled HTML page
        for page in pages:
            html = page_contents.get(page.url, "")
            if not html:
                continue

            page_findings = []
            for analyzer in self.static_analyzers:
                try:
                    findings = analyzer.analyze(page.url, html)
                    page_findings.extend(findings)
                except Exception as e:
                    logger.error(f"Analyzer {analyzer.name} failed on {page.url}: {e}")

            page.findings = page_findings
            all_findings.extend(page_findings)

        # Analyze PDFs
        for pdf_url, pdf_bytes in pdf_contents.items():
            logger.info(f"[{scan_id}] Analyzing PDF: {pdf_url} ({len(pdf_bytes)} bytes)")
            try:
                pdf_findings = self.pdf_analyzer.analyze_pdf(pdf_url, pdf_bytes)
                for page in pages:
                    if page.url == pdf_url:
                        page.findings.extend(pdf_findings)
                        break
                all_findings.extend(pdf_findings)
            except Exception as e:
                logger.error(f"PDF analyzer failed on {pdf_url}: {e}")

        # Analyze agentic files
        for af in agentic_files:
            all_findings.extend(af.findings)  # Already has discovery finding
            for analyzer in self.static_analyzers:
                try:
                    findings = analyzer.analyze_text(af.url, af.content)
                    af.findings.extend(findings)
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error(f"Analyzer {analyzer.name} failed on {af.url}: {e}")

        logger.info(f"[{scan_id}] Static analysis: {len(all_findings)} findings")
        return all_findings

    @staticmethod
    def _dedup_findings(findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings, keeping the highest-severity instance.

        Each finding gets a single canonical fingerprint:
        - If a pattern is identified in the description, use (category, url, pattern_hash)
          This catches the same regex matching in both visible and hidden text.
        - Otherwise, use (category, url, evidence_hash) with aggressive whitespace removal.

        When duplicates share a fingerprint, keep the highest severity.
        """
        import re

        SEVERITY_RANK = {
            Severity.critical: 0,
            Severity.high: 1,
            Severity.medium: 2,
            Severity.low: 3,
            Severity.info: 4,
        }

        seen: dict[str, tuple[int, Finding]] = {}

        for f in findings:
            rank = SEVERITY_RANK.get(f.severity, 5)

            # Try pattern-based fingerprint first (best for cross-extraction dedup)
            pat_match = re.search(r"Pattern:\s*(.{10,50})", f.description or "")
            if pat_match:
                pat_key = pat_match.group(1).strip()
                pat_hash = hashlib.md5(pat_key.encode()).hexdigest()[:12]
                fp = f"{f.category.value}|{f.url}|pat:{pat_hash}"
            else:
                # Fallback: evidence-based fingerprint
                ev_norm = re.sub(r'\s+', '', (f.evidence or "").lower())[:200]
                ev_hash = hashlib.md5(ev_norm.encode()).hexdigest()[:12]
                fp = f"{f.category.value}|{f.url}|ev:{ev_hash}"

            # Prefer higher severity; on tie, prefer "hidden" findings (more informative)
            if fp not in seen:
                seen[fp] = (rank, f)
            elif rank < seen[fp][0]:
                seen[fp] = (rank, f)
            elif rank == seen[fp][0] and "hidden" in f.title.lower():
                seen[fp] = (rank, f)

        return [entry[1] for entry in seen.values()]

    def _compute_summary(
        self, findings: list[Finding], agentic_files, pages_crawled: int = 0
    ) -> ScanSummary:
        """Compute aggregate scan summary with risk score."""
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        # Risk score: weighted sum normalized to 0-100
        weights = settings.severity_weights
        raw_score = (
            counts.get(Severity.critical, 0) * weights["critical"]
            + counts.get(Severity.high, 0) * weights["high"]
            + counts.get(Severity.medium, 0) * weights["medium"]
            + counts.get(Severity.low, 0) * weights["low"]
        )
        risk_score = min(
            100.0,
            raw_score * 2.0 if raw_score < 20
            else 40 + 60 * (1 - math.exp(-raw_score / 50)),
        )

        return ScanSummary(
            total_pages_crawled=pages_crawled,
            total_findings=len(findings),
            critical_count=counts.get(Severity.critical, 0),
            high_count=counts.get(Severity.high, 0),
            medium_count=counts.get(Severity.medium, 0),
            low_count=counts.get(Severity.low, 0),
            info_count=counts.get(Severity.info, 0),
            risk_score=round(risk_score, 1),
            agentic_files_found=len(agentic_files) if agentic_files else 0,
        )

    def _save_results(self, result: ScanResult):
        """Persist scan results to the results/ directory."""
        try:
            RESULTS_DIR.mkdir(parents=True, exist_ok=True)

            # Build filename: timestamp_scanid_domain.json
            domain = urlparse(result.target_url).netloc.replace(":", "_") or "unknown"
            ts = result.started_at.strftime("%Y%m%d_%H%M%S")
            filename = f"{ts}_{result.scan_id}_{domain}.json"
            filepath = RESULTS_DIR / filename

            data = result.model_dump(mode="json")
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2, default=str)

            logger.info(f"[{result.scan_id}] Results saved to {filepath}")
        except Exception as e:
            logger.error(f"[{result.scan_id}] Failed to save results: {e}")

    # ── Rule Learning Helpers ────────────────────────────────────────

    async def _extract_rules_from_findings(
        self, scan_id: str, llm_findings: list[Finding],
    ) -> None:
        """Batch-extract regex rules from LLM judge findings via a single LLM call.

        Sends all LLM-only findings to Claude and parses the response into
        candidate rules stored via RuleManager.
        """
        from rule_manager import RuleManager
        from prompts.rule_extraction_prompt import (
            RULE_EXTRACTION_SYSTEM_PROMPT,
            BATCH_RULE_EXTRACTION_PROMPT,
        )

        if not self.llm_judge.available:
            logger.warning(f"[{scan_id}] Cannot extract rules — no LLM available")
            return

        rules_file = Path(settings.rules_dir) / "learned_rules.json"
        mgr = RuleManager(rules_file)

        # Build the findings block for the prompt
        findings_block_parts = []
        for i, f in enumerate(llm_findings):
            findings_block_parts.append(
                f"--- Finding {i} ---\n"
                f"Title: {f.title}\n"
                f"Severity: {f.severity.value}\n"
                f"Category: {f.category.value}\n"
                f"Description: {f.description}\n"
                f"Evidence: {f.evidence[:500]}\n"
                f"URL: {f.url}\n"
            )
        findings_block = "\n".join(findings_block_parts)

        prompt = BATCH_RULE_EXTRACTION_PROMPT.format(
            count=len(llm_findings),
            findings_block=findings_block,
        )

        logger.info(
            f"[{scan_id}] Extracting rules from {len(llm_findings)} LLM findings..."
        )

        try:
            import anthropic
            import time as _time
            from usage_tracker import usage as _usage
            client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
            t0 = _time.monotonic()
            response = await client.messages.create(
                model=settings.llm_model,
                max_tokens=settings.llm_max_tokens,
                system=RULE_EXTRACTION_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            elapsed_ms = (_time.monotonic() - t0) * 1000
            u = response.usage
            _usage.record(
                model=settings.llm_model,
                purpose="rule_extraction",
                scan_id=scan_id,
                input_tokens=u.input_tokens,
                output_tokens=u.output_tokens,
                duration_ms=elapsed_ms,
                cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
                cache_creation_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
            )
            raw = response.content[0].text.strip()

            # Parse JSON array (handle markdown fences if present)
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            extractions = json.loads(raw)

        except Exception as e:
            logger.error(f"[{scan_id}] Rule extraction LLM call failed: {e}")
            return

        # Process extractions
        created = 0
        for ext in extractions:
            if not ext.get("extractable"):
                continue

            idx = ext.get("finding_index", 0)
            if idx >= len(llm_findings):
                continue
            src = llm_findings[idx]

            # Build test cases
            test_cases = []
            for tc in ext.get("test_cases", []):
                if isinstance(tc, dict) and "text" in tc:
                    from models import RuleTestCase
                    test_cases.append(RuleTestCase(
                        text=tc["text"],
                        should_match=tc.get("should_match", True),
                    ))

            confidence = float(ext.get("confidence", 0.5))
            if confidence < settings.rule_min_confidence:
                logger.debug(
                    f"[{scan_id}] Skipping low-confidence extraction "
                    f"(confidence={confidence:.0%})"
                )
                continue

            rule = mgr.add_candidate(
                regex_pattern=ext["regex_pattern"],
                title=src.title,
                severity=src.severity,
                category=src.category,
                scan_id=scan_id,
                evidence=src.evidence,
                source_url=src.url,
                test_cases=test_cases,
                confidence=confidence,
                description=ext.get("explanation", src.description),
                recommendation=src.recommendation,
            )
            if rule:
                created += 1

        logger.info(
            f"[{scan_id}] Rule extraction complete: "
            f"{created} candidate rules created from {len(llm_findings)} findings"
        )

    def _confirm_learned_rule_matches(
        self, scan_id: str, findings: list[Finding],
    ) -> None:
        """Track re-confirmations when learned rules match in this scan.

        When a finding came from the learned_rules analyzer, call
        RuleManager.confirm() to build validation evidence.
        """
        learned = [f for f in findings if f.analyzer == "learned_rules"]
        if not learned:
            return

        from rule_manager import RuleManager
        rules_file = Path(settings.rules_dir) / "learned_rules.json"
        mgr = RuleManager(rules_file)

        confirmed = 0
        for f in learned:
            # Extract rule_id from description (format: "...rule_id=XXXX, ...")
            import re
            match = re.search(r"rule_id=(\S+?)[\s,)]", f.description or "")
            if match:
                rule_id = match.group(1)
                result = mgr.confirm(rule_id, scan_id)
                if result:
                    confirmed += 1

        if confirmed:
            logger.info(
                f"[{scan_id}] Confirmed {confirmed} learned rule matches"
            )
