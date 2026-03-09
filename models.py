"""Pydantic models for AASA."""

from __future__ import annotations
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional
from enum import Enum
from datetime import datetime


# ── Enums ─────────────────────────────────────────────────────────────

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingCategory(str, Enum):
    prompt_injection = "prompt_injection"
    hidden_text = "hidden_text"
    metadata_abuse = "metadata_abuse"
    tool_pattern = "tool_pattern"
    exfiltration = "exfiltration"
    markdown_injection = "markdown_injection"
    agentic_signal = "agentic_signal"
    iframe_injection = "iframe_injection"
    robots_directive = "robots_directive"
    llm_judge = "llm_judge"


# ── Findings ──────────────────────────────────────────────────────────

class Finding(BaseModel):
    """A single security finding."""
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    evidence: str = Field(default="", description="Raw snippet that triggered the finding")
    url: str = Field(default="", description="URL where finding was discovered")
    line_number: Optional[int] = None
    analyzer: str = Field(default="", description="Name of analyzer that produced this")
    recommendation: str = ""


class AgenticFile(BaseModel):
    """An agentic signal file discovered during crawl."""
    filename: str
    url: str
    content: str = ""
    size: int = 0
    findings: list[Finding] = []


class CrawledPage(BaseModel):
    """A page visited by the crawler."""
    url: str
    status_code: int = 0
    content_type: str = ""
    title: str = ""
    depth: int = 0
    links_found: int = 0
    findings: list[Finding] = []


# ── Scan Request / Response ───────────────────────────────────────────

class ScanRequest(BaseModel):
    """Request to scan a URL."""
    url: str = Field(..., description="Target URL to scan")
    max_depth: int = Field(default=2, ge=0, le=5, description="Crawl depth")
    max_pages: int = Field(default=50, ge=1, le=500, description="Max pages to crawl")
    enable_llm_judge: bool = Field(default=True, description="Enable LLM-as-judge analysis")
    static_only: bool = Field(default=False, description="Skip LLM analysis, static rules only")


class ScanSummary(BaseModel):
    """High-level scan summary."""
    total_pages_crawled: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    risk_score: float = Field(default=0.0, description="Aggregate risk score 0-100")
    agentic_files_found: int = 0


class ScanResult(BaseModel):
    """Full scan result."""
    scan_id: str
    target_url: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "running"
    summary: ScanSummary = ScanSummary()
    pages: list[CrawledPage] = []
    agentic_files: list[AgenticFile] = []
    findings: list[Finding] = []
    llm_judge_analysis: Optional[str] = None


# ── Rule Learning ─────────────────────────────────────────────────────

class RuleState(str, Enum):
    """Lifecycle state of a learned rule."""
    candidate = "candidate"
    validated = "validated"
    active = "active"
    rejected = "rejected"


class RuleTestCase(BaseModel):
    """Test case for validating a learned rule."""
    text: str = Field(..., description="Sample text to test against")
    should_match: bool = Field(..., description="Whether the regex should match this text")


class LearnedRule(BaseModel):
    """A regex rule extracted from an LLM judge finding."""
    rule_id: str
    regex_pattern: str
    title: str
    severity: Severity
    category: FindingCategory
    state: RuleState = RuleState.candidate
    description: str = ""
    recommendation: str = ""

    # Provenance
    created_at: datetime
    created_from_scan_id: str = ""
    source_url: str = Field(
        default="", description="URL of the document/page that triggered this rule"
    )
    source_finding_evidence: str = Field(
        default="", description="Original evidence from LLM finding"
    )

    # Validation & confidence
    test_cases: list[RuleTestCase] = []
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    validation_count: int = 0
    confirmed_scan_ids: list[str] = []
    last_confirmed_at: Optional[datetime] = None
    true_positive_count: int = 0
    false_positive_count: int = 0


class RulesDB(BaseModel):
    """Persistent container for all learned rules."""
    rules: list[LearnedRule] = []
    version: str = "1.0"
    last_updated: Optional[datetime] = None


# ── Health ────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    llm_judge_available: bool
