"""FastAPI routes for AASA."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, Response
from pydantic import BaseModel, Field

from config import settings
from models import ScanRequest, ScanResult, HealthResponse, RuleState
from scanner import Scanner, RESULTS_DIR
from rule_manager import RuleManager
from usage_tracker import usage as usage_tracker

logger = logging.getLogger(__name__)
router = APIRouter()

# In-memory scan storage (replace with DB for production)
scans: Dict[str, ScanResult] = {}
scanner = Scanner()


# ── Extra request models ──────────────────────────────────────────────

class PDFScanRequest(BaseModel):
    """Request to scan a single PDF URL."""
    url: str = Field(..., description="Direct URL to a PDF file")
    enable_llm_judge: bool = Field(default=False, description="Enable LLM-as-judge analysis on extracted PDF text")


class APIScanRequest(BaseModel):
    """Request to scan for API endpoints."""
    url: str = Field(..., description="Base URL to probe for API endpoints")
    probe_endpoints: bool = Field(
        default=False,
        description="If true, also probe individual endpoints found in OpenAPI/Swagger specs",
    )
    enable_llm_review: bool = Field(
        default=False,
        description="If true, use LLM to deep-review discovered API specs and response bodies",
    )


class PromoteRequest(BaseModel):
    """Request to promote a rule to a new state."""
    target_state: str = Field(..., description="Target state: 'validated', 'active', or 'rejected'")


class TestRuleRequest(BaseModel):
    """Request to test a regex against sample text."""
    test_string: str = Field(..., description="Text to test the regex against")


# ── System ────────────────────────────────────────────────────────────

@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    tags=["system"],
)
async def health():
    """Check service health and LLM judge availability."""
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        llm_judge_available=scanner.llm_judge.available,
    )


@router.get(
    "/analyzers",
    summary="List available analyzers",
    tags=["system"],
    description="List all static rule-based analyzers and the agentic LLM judge analyzer.",
)
async def list_analyzers():
    """List all available static and agentic analyzers."""
    from analyzers import ALL_STATIC_ANALYZERS
    static = [
        {"name": cls.name, "description": cls.description, "type": "static"}
        for cls in ALL_STATIC_ANALYZERS
    ]
    static.append({
        "name": "pdf_analyzer",
        "description": scanner.pdf_analyzer.description,
        "type": "static",
    })
    agentic = {
        "name": "llm_judge",
        "description": "LLM-as-judge analysis using Claude",
        "type": "agentic",
        "available": scanner.llm_judge.available,
        "model": settings.llm_model,
    }
    return {"static_analyzers": static, "agentic_analyzer": agentic}


# ── Scanning ──────────────────────────────────────────────────────────

@router.post(
    "/scan",
    summary="Start a full attack surface scan (async)",
    tags=["scanning"],
    description=(
        "Start a background scan of the target URL. Returns a scan_id immediately. "
        "Poll GET /scan/{scan_id} to track progress. Status transitions: "
        "queued → crawling → analyzing → llm_analysis → completed (or failed)."
    ),
)
async def run_scan(request: ScanRequest):
    """Start a non-blocking scan and return scan_id immediately.

    Uses asyncio.create_task() to run the scan as a truly concurrent
    coroutine. CPU-bound static analysis runs in a thread pool (via
    asyncio.to_thread in Scanner.scan), so the event loop stays free
    to handle polling, history, and other requests.
    """
    import uuid
    from datetime import datetime, timezone
    scan_id = str(uuid.uuid4())[:8]

    result = ScanResult(
        scan_id=scan_id,
        target_url=request.url,
        started_at=datetime.now(timezone.utc),
        status="queued",
    )
    scans[scan_id] = result

    async def _run():
        try:
            await scanner.scan(request, result=result)
        except Exception as e:
            logger.exception(f"Scan {scan_id} failed: {e}")
            result.status = f"failed: {e}"

    asyncio.create_task(_run())
    return {"scan_id": scan_id, "status": "queued", "target_url": request.url}


@router.post(
    "/scan/sync",
    response_model=ScanResult,
    summary="Run full attack surface scan (blocking)",
    tags=["scanning"],
    description=(
        "Crawl a target URL synchronously and return full results. "
        "Use POST /scan for non-blocking operation."
    ),
)
async def run_scan_sync(request: ScanRequest):
    """Run a synchronous scan and return results."""
    try:
        result = await scanner.scan(request)
        scans[result.scan_id] = result
        return result
    except Exception as e:
        logger.exception(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post(
    "/scan/pdf",
    summary="Start a PDF scan (async)",
    tags=["scanning"],
    description=(
        "Download and deeply analyze a single PDF file in the background. "
        "Returns scan_id immediately. Poll GET /scan/{scan_id} for results. "
        "Optionally enables LLM-as-judge analysis on extracted PDF text."
    ),
)
async def scan_pdf(request: PDFScanRequest):
    """Start a non-blocking PDF scan."""
    import uuid
    from datetime import datetime, timezone
    scan_id = str(uuid.uuid4())[:8]

    result = ScanResult(
        scan_id=scan_id,
        target_url=request.url,
        started_at=datetime.now(timezone.utc),
        status="queued",
    )
    scans[scan_id] = result

    async def _run():
        try:
            await scanner.scan_pdf_url(
                request.url,
                enable_llm_judge=request.enable_llm_judge,
                result=result,
            )
        except Exception as e:
            logger.exception(f"PDF scan {scan_id} failed: {e}")
            result.status = f"failed: {e}"

    asyncio.create_task(_run())
    return {"scan_id": scan_id, "status": "queued", "target_url": request.url}


@router.post(
    "/scan/pdf/sync",
    response_model=ScanResult,
    summary="Scan a single PDF (blocking)",
    tags=["scanning"],
    description="Download and analyze a PDF synchronously. Use POST /scan/pdf for non-blocking.",
)
async def scan_pdf_sync(request: PDFScanRequest):
    """Scan a single PDF URL synchronously."""
    try:
        result = await scanner.scan_pdf_url(
            request.url,
            enable_llm_judge=request.enable_llm_judge,
        )
        scans[result.scan_id] = result
        return result
    except Exception as e:
        logger.exception(f"PDF scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"PDF scan failed: {str(e)}")


@router.post(
    "/scan/api",
    summary="Start an API discovery scan (async)",
    tags=["scanning"],
    description=(
        "Probe a target URL for well-known API endpoints (OpenAPI, Swagger, "
        "GraphQL, actuator, admin, debug, health, etc.). Returns scan_id immediately. "
        "Poll GET /scan/{scan_id} for results. Enable probe_endpoints to also test "
        "individual API endpoints discovered in specs for unauthenticated access."
    ),
)
async def scan_api(request: APIScanRequest):
    """Start a non-blocking API discovery scan."""
    import uuid
    from datetime import datetime, timezone
    scan_id = str(uuid.uuid4())[:8]

    result = ScanResult(
        scan_id=scan_id,
        target_url=request.url,
        started_at=datetime.now(timezone.utc),
        status="queued",
    )
    scans[scan_id] = result

    async def _run():
        try:
            await scanner.scan_api(
                request.url,
                probe_endpoints=request.probe_endpoints,
                enable_llm_review=request.enable_llm_review,
                result=result,
            )
        except Exception as e:
            logger.exception(f"API scan {scan_id} failed: {e}")
            result.status = f"failed: {e}"

    asyncio.create_task(_run())
    return {"scan_id": scan_id, "status": "queued", "target_url": request.url}


@router.get(
    "/scan/{scan_id}",
    response_model=ScanResult,
    summary="Get scan results / poll status",
    tags=["scanning"],
    description=(
        "Retrieve scan results or current status. Use this to poll async scans. "
        "Check the 'status' field: queued, crawling, analyzing, llm_analysis, "
        "completed, or failed."
    ),
)
async def get_scan(scan_id: str):
    """Get scan results by ID.

    Checks in-memory scans first (for active/recent scans), then falls
    back to persisted result files on disk so polling still works after
    a container restart.
    """
    if scan_id in scans:
        return scans[scan_id]

    # Fall back: search persisted results on disk
    if RESULTS_DIR.exists():
        for f in RESULTS_DIR.glob(f"*_{scan_id}_*.json"):
            try:
                with open(f) as fh:
                    data = json.load(fh)
                return data
            except Exception:
                pass

    raise HTTPException(status_code=404, detail="Scan not found")


@router.get(
    "/scans",
    summary="List all scans (in-memory)",
    tags=["scanning"],
)
async def list_scans():
    """List all scan IDs with status from current session."""
    return [
        {
            "scan_id": s.scan_id,
            "target_url": s.target_url,
            "status": s.status,
            "started_at": s.started_at.isoformat(),
            "risk_score": s.summary.risk_score,
            "total_findings": s.summary.total_findings,
        }
        for s in scans.values()
    ]


# ── Persisted Results ─────────────────────────────────────────────────

@router.get(
    "/results",
    summary="List persisted scan results",
    tags=["results"],
    description="List all scan result files saved to the results/ directory.",
)
async def list_results():
    """List all persisted result files."""
    if not RESULTS_DIR.exists():
        return []

    files = sorted(
        (f for f in RESULTS_DIR.glob("*.json") if f.name not in ("learned_rules.json", "llm_usage.json")),
        reverse=True,
    )
    results = []
    for f in files:
        try:
            with open(f) as fh:
                data = json.load(fh)
            results.append({
                "filename": f.name,
                "scan_id": data.get("scan_id", ""),
                "target_url": data.get("target_url", ""),
                "status": data.get("status", ""),
                "started_at": data.get("started_at", ""),
                "risk_score": data.get("summary", {}).get("risk_score", 0),
                "total_findings": data.get("summary", {}).get("total_findings", 0),
            })
        except Exception:
            results.append({"filename": f.name, "error": "Could not parse"})

    return results


@router.get(
    "/results/{filename}",
    summary="Get persisted scan result",
    tags=["results"],
    description="Load a specific scan result from the results/ directory by filename.",
)
async def get_result(filename: str):
    """Load a persisted result file."""
    filepath = RESULTS_DIR / filename
    if not filepath.exists() or not filepath.suffix == ".json":
        raise HTTPException(status_code=404, detail="Result file not found")

    try:
        with open(filepath) as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read result: {e}")


# ── Learned Rules ─────────────────────────────────────────────────

def _get_rule_manager() -> RuleManager:
    """Get a RuleManager instance (reads from persistent file)."""
    return RuleManager()


@router.get(
    "/rules",
    summary="List learned rules",
    tags=["rules"],
    description=(
        "List all learned rules. Optionally filter by state: "
        "candidate, validated, active, rejected."
    ),
)
async def list_rules(state: str | None = None):
    """List all learned rules, optionally filtered by state."""
    mgr = _get_rule_manager()
    if state:
        try:
            rule_state = RuleState(state)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid state: {state}. Must be one of: "
                f"{', '.join(s.value for s in RuleState)}",
            )
        rules = mgr.get_rules_by_state(rule_state)
    else:
        rules = mgr.db.rules

    return {
        "total": len(rules),
        "rules": [r.model_dump(mode="json") for r in rules],
    }


@router.get(
    "/rules/stats",
    summary="Rule statistics",
    tags=["rules"],
    description="Get aggregate statistics about the learned rules database.",
)
async def rule_stats():
    """Get rule database statistics."""
    mgr = _get_rule_manager()
    return mgr.stats()


@router.post(
    "/rules/{rule_id}/promote",
    summary="Promote a rule",
    tags=["rules"],
    description=(
        "Change a rule's state. Valid transitions: "
        "candidate → validated/active/rejected, "
        "validated → active/rejected, "
        "active → rejected, "
        "rejected → candidate."
    ),
)
async def promote_rule(rule_id: str, request: PromoteRequest):
    """Promote a rule to a new lifecycle state."""
    mgr = _get_rule_manager()
    try:
        target = RuleState(request.target_state)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target_state: {request.target_state}",
        )
    try:
        rule = mgr.promote(rule_id, target)
        # Reload the scanner's learned rule analyzer so it picks up changes
        scanner.learned_rule_analyzer.reload()
        return rule.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post(
    "/rules/{rule_id}/reject",
    summary="Reject a rule",
    tags=["rules"],
)
async def reject_rule(rule_id: str):
    """Mark a rule as rejected."""
    mgr = _get_rule_manager()
    rule = mgr.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    mgr.reject(rule_id)
    scanner.learned_rule_analyzer.reload()
    return {"status": "rejected", "rule_id": rule_id}


@router.delete(
    "/rules/{rule_id}",
    summary="Delete a rule",
    tags=["rules"],
    description="Permanently delete a rule from the database.",
)
async def delete_rule(rule_id: str):
    """Hard-delete a rule."""
    mgr = _get_rule_manager()
    if mgr.delete(rule_id):
        scanner.learned_rule_analyzer.reload()
        return {"status": "deleted", "rule_id": rule_id}
    raise HTTPException(status_code=404, detail="Rule not found")


@router.post(
    "/rules/{rule_id}/test",
    summary="Test a rule's regex",
    tags=["rules"],
    description="Run a rule's regex pattern against a test string and return match info.",
)
async def test_rule(rule_id: str, request: TestRuleRequest):
    """Test a rule's regex against sample text."""
    mgr = _get_rule_manager()
    rule = mgr.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return RuleManager.test_rule(rule.regex_pattern, request.test_string)


# ── LLM Usage ─────────────────────────────────────────────────────

@router.get(
    "/usage",
    summary="LLM usage overview",
    tags=["usage"],
    description="Get token usage, cost breakdown by model/purpose/scan, and full call log.",
)
async def get_usage():
    """Return aggregated LLM usage statistics."""
    return usage_tracker.summary()


@router.post(
    "/usage/reset",
    summary="Reset usage counters",
    tags=["usage"],
)
async def reset_usage():
    """Clear all recorded usage data."""
    usage_tracker.reset()
    return {"status": "reset"}


# ── Demo Mode ────────────────────────────────────────────────────

DEMO_FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures"

# In-memory tracking for demo runs
_demo_state: Dict[str, str] = {}  # "status", "website_scan_id", "pdf_scan_id"


@router.get(
    "/demo/fixtures/page",
    summary="Serve demo poisoned webpage",
    tags=["demo"],
    response_class=HTMLResponse,
)
async def demo_fixture_page():
    """Serve the built-in poisoned HTML test page."""
    html_file = DEMO_FIXTURES / "poisoned_page.html"
    if not html_file.exists():
        raise HTTPException(status_code=404, detail="Demo fixture not found")
    return HTMLResponse(content=html_file.read_text(), status_code=200)


@router.get(
    "/demo/fixtures/poisoned.pdf",
    summary="Serve demo poisoned PDF",
    tags=["demo"],
)
async def demo_fixture_pdf():
    """Serve the built-in poisoned PDF test file."""
    pdf_file = DEMO_FIXTURES / "poisoned.pdf"
    if not pdf_file.exists():
        # Try to generate it
        try:
            import subprocess
            create_script = DEMO_FIXTURES.parent / "create_test_pdf.py"
            if create_script.exists():
                subprocess.run(
                    ["python", str(create_script)],
                    capture_output=True, timeout=10,
                )
        except Exception:
            pass
    if not pdf_file.exists():
        raise HTTPException(status_code=404, detail="Demo PDF fixture not found")
    return Response(
        content=pdf_file.read_bytes(),
        media_type="application/pdf",
        headers={"Content-Disposition": "inline; filename=poisoned.pdf"},
    )


@router.post(
    "/demo/run",
    summary="Run demo scans",
    tags=["demo"],
    description=(
        "Launch demo scans against built-in poisoned fixtures (HTML page + PDF). "
        "Both scans run with LLM Judge enabled to generate candidate rules. "
        "Returns scan IDs for polling."
    ),
)
async def run_demo():
    """Kick off demo scans against built-in poisoned fixtures.

    Starts both a website scan and a PDF scan in the background.
    The frontend polls scan status as usual.
    """
    import uuid
    from datetime import datetime, timezone

    # Determine the base URL to serve fixtures from
    # We use the internal server URL since the fixtures are served by this app
    base_url = f"http://localhost:{settings.port}/api/v1/demo/fixtures"

    results = {}

    # 1. Website scan
    website_scan_id = str(uuid.uuid4())[:8]
    website_result = ScanResult(
        scan_id=website_scan_id,
        target_url=f"{base_url}/page",
        started_at=datetime.now(timezone.utc),
        status="queued",
    )
    scans[website_scan_id] = website_result

    async def _run_website():
        try:
            req = ScanRequest(
                url=f"{base_url}/page",
                max_depth=0,
                max_pages=1,
                enable_llm_judge=True,
                static_only=False,
            )
            await scanner.scan(req, result=website_result)
        except Exception as e:
            logger.exception(f"Demo website scan failed: {e}")
            website_result.status = f"failed: {e}"

    asyncio.create_task(_run_website())
    results["website_scan_id"] = website_scan_id

    # 2. PDF scan
    pdf_scan_id = str(uuid.uuid4())[:8]
    pdf_result = ScanResult(
        scan_id=pdf_scan_id,
        target_url=f"{base_url}/poisoned.pdf",
        started_at=datetime.now(timezone.utc),
        status="queued",
    )
    scans[pdf_scan_id] = pdf_result

    async def _run_pdf():
        try:
            await scanner.scan_pdf_url(
                f"{base_url}/poisoned.pdf",
                enable_llm_judge=True,
                result=pdf_result,
            )
        except Exception as e:
            logger.exception(f"Demo PDF scan failed: {e}")
            pdf_result.status = f"failed: {e}"

    asyncio.create_task(_run_pdf())
    results["pdf_scan_id"] = pdf_scan_id

    return {
        "status": "started",
        "message": "Demo scans launched: poisoned webpage + poisoned PDF (both with LLM Judge)",
        **results,
    }


@router.get(
    "/demo/status",
    summary="Get demo scan status",
    tags=["demo"],
)
async def demo_status():
    """Check status of any running demo scans."""
    demo_scans = []
    for scan_id, result in scans.items():
        url = result.target_url or ""
        if "/demo/fixtures/" in url:
            demo_scans.append({
                "scan_id": scan_id,
                "target_url": url,
                "status": result.status,
                "type": "pdf" if url.endswith(".pdf") else "website",
                "findings_count": len(result.findings) if result.findings else 0,
                "risk_score": result.summary.risk_score if result.summary else 0,
            })
    return {"demo_scans": demo_scans}
