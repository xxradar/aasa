#!/usr/bin/env python3
"""CLI interface for AI Agent Attack Surface Analyzer."""

from __future__ import annotations

import asyncio
import json
import sys
import argparse
import logging
from datetime import datetime, timezone

from config import settings
from models import ScanRequest, Severity
from scanner import Scanner


# ── Colors ────────────────────────────────────────────────────────────

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_GREEN = "\033[42m"


SEVERITY_COLORS = {
    Severity.critical: f"{C.BG_RED}{C.WHITE}{C.BOLD}",
    Severity.high: f"{C.RED}{C.BOLD}",
    Severity.medium: f"{C.YELLOW}",
    Severity.low: f"{C.DIM}",
    Severity.info: f"{C.DIM}",
}

SEVERITY_ICONS = {
    Severity.critical: "!!!",
    Severity.high: " !! ",
    Severity.medium: " !  ",
    Severity.low: " .  ",
    Severity.info: " i  ",
}


def banner():
    print(f"""{C.CYAN}{C.BOLD}
    ╔══════════════════════════════════════════════════════╗
    ║   AI Agent Attack Surface Analyzer (AASA) v{settings.app_version}     ║
    ║   Indirect Prompt Injection & Agent Security Scanner ║
    ╚══════════════════════════════════════════════════════╝{C.RESET}
    """)


def print_finding(f, index: int):
    color = SEVERITY_COLORS.get(f.severity, "")
    icon = SEVERITY_ICONS.get(f.severity, "")
    print(f"  {color}[{icon}]{C.RESET} {C.BOLD}{f.title}{C.RESET}")
    print(f"       Category: {f.category.value} | Severity: {f.severity.value.upper()}")
    print(f"       URL: {f.url}")
    if f.evidence:
        evidence = f.evidence.replace("\n", " ")[:120]
        print(f"       Evidence: {C.DIM}{evidence}{C.RESET}")
    if f.recommendation:
        print(f"       Fix: {C.GREEN}{f.recommendation[:120]}{C.RESET}")
    print()


def risk_bar(score: float) -> str:
    """ASCII risk bar."""
    filled = int(score / 5)
    empty = 20 - filled
    if score >= 70:
        color = C.RED
    elif score >= 40:
        color = C.YELLOW
    else:
        color = C.GREEN
    return f"{color}{'█' * filled}{'░' * empty}{C.RESET} {score:.1f}/100"


def print_results(result):
    """Shared result printer for both scan modes."""
    s = result.summary
    print(f"  {C.BOLD}═══ SCAN RESULTS ═══{C.RESET}")
    print()
    print(f"  Risk Score:    {risk_bar(s.risk_score)}")
    print(f"  Pages Crawled: {s.total_pages_crawled}")
    print(f"  Agentic Files: {s.agentic_files_found}")
    print(f"  Total Findings: {s.total_findings}")
    print()

    if s.critical_count:
        print(f"    {C.BG_RED}{C.WHITE} CRITICAL {C.RESET} {s.critical_count}")
    if s.high_count:
        print(f"    {C.RED} HIGH     {C.RESET} {s.high_count}")
    if s.medium_count:
        print(f"    {C.YELLOW} MEDIUM   {C.RESET} {s.medium_count}")
    if s.low_count:
        print(f"    {C.DIM} LOW      {C.RESET} {s.low_count}")
    if s.info_count:
        print(f"    {C.DIM} INFO     {C.RESET} {s.info_count}")
    print()

    # ── Agentic Files ─────────────────────────────────────────
    if result.agentic_files:
        print(f"  {C.BOLD}═══ AGENTIC FILES ═══{C.RESET}")
        for af in result.agentic_files:
            print(f"    {C.MAGENTA}{af.filename}{C.RESET} ({af.size} bytes) — {af.url}")
        print()

    # ── Findings ──────────────────────────────────────────────
    if result.findings:
        severity_order = {Severity.critical: 0, Severity.high: 1, Severity.medium: 2, Severity.low: 3, Severity.info: 4}
        sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 5))

        print(f"  {C.BOLD}═══ FINDINGS ═══{C.RESET}")
        print()
        for i, f in enumerate(sorted_findings, 1):
            print_finding(f, i)

    # ── LLM Judge Summary ─────────────────────────────────────
    if result.llm_judge_analysis:
        print(f"  {C.BOLD}═══ LLM JUDGE ANALYSIS ═══{C.RESET}")
        print()
        print(f"  {result.llm_judge_analysis[:2000]}")
        print()


async def run_scan(args):
    """Run a full website scan."""
    banner()

    request = ScanRequest(
        url=args.url,
        max_depth=args.depth,
        max_pages=args.max_pages,
        enable_llm_judge=not args.no_llm,
        static_only=args.static_only,
    )

    print(f"  {C.CYAN}Target:{C.RESET}     {args.url}")
    print(f"  {C.CYAN}Max Depth:{C.RESET}  {args.depth}")
    print(f"  {C.CYAN}Max Pages:{C.RESET}  {args.max_pages}")
    print(f"  {C.CYAN}LLM Judge:{C.RESET}  {'Disabled' if args.no_llm or args.static_only else 'Enabled'}")
    print()

    scanner = Scanner()

    print(f"  {C.BOLD}Scanning...{C.RESET}")
    print()

    result = await scanner.scan(request)
    print_results(result)

    # ── Output ────────────────────────────────────────────────
    if args.output:
        with open(args.output, "w") as f:
            json.dump(result.model_dump(mode="json"), f, indent=2, default=str)
        print(f"  {C.GREEN}Results saved to: {args.output}{C.RESET}")

    if args.json:
        print(json.dumps(result.model_dump(mode="json"), indent=2, default=str))


async def run_pdf_scan(args):
    """Run a direct PDF scan."""
    banner()

    use_llm = not args.no_llm and not args.static_only
    print(f"  {C.CYAN}Mode:{C.RESET}       PDF Direct Scan")
    print(f"  {C.CYAN}Target:{C.RESET}     {args.pdf}")
    print(f"  {C.CYAN}LLM Judge:{C.RESET}  {'Enabled' if use_llm else 'Disabled'}")
    print()

    scanner = Scanner()

    print(f"  {C.BOLD}Downloading and analyzing PDF...{C.RESET}")
    print()

    result = await scanner.scan_pdf_url(args.pdf, enable_llm_judge=use_llm)

    if result.status.startswith("failed"):
        print(f"  {C.RED}FAILED: {result.status}{C.RESET}")
        sys.exit(1)

    print_results(result)

    # ── Output ────────────────────────────────────────────────
    if args.output:
        with open(args.output, "w") as f:
            json.dump(result.model_dump(mode="json"), f, indent=2, default=str)
        print(f"  {C.GREEN}Results saved to: {args.output}{C.RESET}")

    if args.json:
        print(json.dumps(result.model_dump(mode="json"), indent=2, default=str))


def main():
    parser = argparse.ArgumentParser(
        description="AI Agent Attack Surface Analyzer — scan websites and PDFs for indirect prompt injection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Website scan
  aasa https://example.com
  aasa https://example.com --depth 3 --max-pages 100
  aasa https://example.com --static-only --output report.json

  # Direct PDF scan
  aasa --pdf https://example.com/document.pdf
  aasa --pdf https://example.com/cv.pdf --output report.json
  aasa --pdf https://example.com/cv.pdf --json | jq '.summary'
        """,
    )
    parser.add_argument("url", nargs="?", help="Target URL to scan (website mode)")
    parser.add_argument("--pdf", metavar="URL", help="Direct PDF scan mode — analyze a single PDF URL")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM-as-judge analysis")
    parser.add_argument("--static-only", action="store_true", help="Static analysis only (no LLM)")
    parser.add_argument("--output", "-o", help="Save JSON results to file")
    parser.add_argument("--json", action="store_true", help="Output raw JSON to stdout")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    # Determine scan mode
    if args.pdf:
        asyncio.run(run_pdf_scan(args))
    elif args.url:
        asyncio.run(run_scan(args))
    else:
        parser.error("Provide a URL for website scan, or use --pdf URL for direct PDF scan")


if __name__ == "__main__":
    main()
