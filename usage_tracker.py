"""LLM usage tracker — records tokens, costs, and model info per API call.

Persists call history to disk so data survives container restarts.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Storage path ───────────────────────────────────────────────────
RESULTS_DIR = Path(os.environ.get("AASA_RESULTS_DIR", "/app/results"))
USAGE_FILE = RESULTS_DIR / "llm_usage.json"

# ── Pricing (per million tokens) ────────────────────────────────────
# Update these when prices change.  Values are USD per 1M tokens.
MODEL_PRICING: dict[str, dict[str, float]] = {
    "claude-sonnet-4-5-20250929": {"input": 3.00, "output": 15.00},
    "claude-sonnet-4-20250514":   {"input": 3.00, "output": 15.00},
    "claude-haiku-4-5-20251001":  {"input": 0.80, "output":  4.00},
    "claude-opus-4-20250514":     {"input": 15.00, "output": 75.00},
    # fallback for unknown models
    "_default":                   {"input": 3.00, "output": 15.00},
}


def _get_pricing(model: str) -> dict[str, float]:
    return MODEL_PRICING.get(model, MODEL_PRICING["_default"])


@dataclass
class LLMCall:
    """A single recorded LLM API call."""
    timestamp: str
    model: str
    purpose: str          # e.g. "llm_judge:page", "llm_judge:summary", "rule_extraction"
    scan_id: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    cost_usd: float
    duration_ms: float = 0.0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0


@dataclass
class UsageTracker:
    """Thread-safe singleton that accumulates LLM usage across the process.

    Persists all calls to ``llm_usage.json`` in the results directory so
    usage history survives container restarts.
    """
    calls: list[LLMCall] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _dirty: bool = field(default=False, repr=False)

    # ── Persistence helpers ────────────────────────────────────────

    def _load(self) -> None:
        """Load previously persisted calls from disk (called once at init)."""
        if not USAGE_FILE.exists():
            return
        try:
            with open(USAGE_FILE) as fh:
                data = json.load(fh)
            loaded = 0
            for raw in data.get("calls", []):
                self.calls.append(LLMCall(
                    timestamp=raw.get("timestamp", ""),
                    model=raw.get("model", ""),
                    purpose=raw.get("purpose", ""),
                    scan_id=raw.get("scan_id", ""),
                    input_tokens=raw.get("input_tokens", 0),
                    output_tokens=raw.get("output_tokens", 0),
                    total_tokens=raw.get("total_tokens", 0),
                    cost_usd=raw.get("cost_usd", 0.0),
                    duration_ms=raw.get("duration_ms", 0.0),
                    cache_read_tokens=raw.get("cache_read_tokens", 0),
                    cache_creation_tokens=raw.get("cache_creation_tokens", 0),
                ))
                loaded += 1
            logger.info(f"Loaded {loaded} previous LLM usage records from {USAGE_FILE}")
        except Exception as exc:
            logger.warning(f"Could not load usage history: {exc}")

    def _save(self) -> None:
        """Persist all calls to disk.  Called after every record()."""
        try:
            RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            payload = {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "total_calls": len(self.calls),
                "calls": [asdict(c) for c in self.calls],
            }
            tmp = USAGE_FILE.with_suffix(".tmp")
            with open(tmp, "w") as fh:
                json.dump(payload, fh, indent=2)
            tmp.replace(USAGE_FILE)          # atomic on POSIX
        except Exception as exc:
            logger.warning(f"Could not persist usage history: {exc}")

    # ── Public API ─────────────────────────────────────────────────

    def record(
        self,
        model: str,
        purpose: str,
        scan_id: str,
        input_tokens: int,
        output_tokens: int,
        duration_ms: float = 0.0,
        cache_read_tokens: int = 0,
        cache_creation_tokens: int = 0,
    ) -> LLMCall:
        """Record a single LLM API call."""
        pricing = _get_pricing(model)
        cost = (
            input_tokens * pricing["input"] / 1_000_000
            + output_tokens * pricing["output"] / 1_000_000
        )

        entry = LLMCall(
            timestamp=datetime.now(timezone.utc).isoformat(),
            model=model,
            purpose=purpose,
            scan_id=scan_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            cost_usd=round(cost, 6),
            duration_ms=round(duration_ms, 1),
            cache_read_tokens=cache_read_tokens,
            cache_creation_tokens=cache_creation_tokens,
        )

        with self._lock:
            self.calls.append(entry)
            self._save()

        logger.info(
            f"LLM call: {purpose} | {model} | "
            f"{input_tokens}+{output_tokens} tokens | ${cost:.4f}"
        )
        return entry

    def summary(self) -> dict:
        """Aggregate usage statistics."""
        with self._lock:
            calls = list(self.calls)

        if not calls:
            return {
                "total_calls": 0,
                "total_input_tokens": 0,
                "total_output_tokens": 0,
                "total_tokens": 0,
                "total_cost_usd": 0.0,
                "total_cache_read_tokens": 0,
                "total_cache_creation_tokens": 0,
                "by_purpose": {},
                "by_model": {},
                "by_scan": {},
                "calls": [],
            }

        total_input = sum(c.input_tokens for c in calls)
        total_output = sum(c.output_tokens for c in calls)
        total_cost = sum(c.cost_usd for c in calls)
        total_cache_read = sum(c.cache_read_tokens for c in calls)
        total_cache_creation = sum(c.cache_creation_tokens for c in calls)

        # Group by purpose
        by_purpose: dict[str, dict] = {}
        for c in calls:
            bp = by_purpose.setdefault(c.purpose, {
                "calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0,
            })
            bp["calls"] += 1
            bp["input_tokens"] += c.input_tokens
            bp["output_tokens"] += c.output_tokens
            bp["cost_usd"] = round(bp["cost_usd"] + c.cost_usd, 6)

        # Group by model
        by_model: dict[str, dict] = {}
        for c in calls:
            bm = by_model.setdefault(c.model, {
                "calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0,
            })
            bm["calls"] += 1
            bm["input_tokens"] += c.input_tokens
            bm["output_tokens"] += c.output_tokens
            bm["cost_usd"] = round(bm["cost_usd"] + c.cost_usd, 6)

        # Group by scan
        by_scan: dict[str, dict] = {}
        for c in calls:
            bs = by_scan.setdefault(c.scan_id, {
                "calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0,
            })
            bs["calls"] += 1
            bs["input_tokens"] += c.input_tokens
            bs["output_tokens"] += c.output_tokens
            bs["cost_usd"] = round(bs["cost_usd"] + c.cost_usd, 6)

        return {
            "total_calls": len(calls),
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_tokens": total_input + total_output,
            "total_cost_usd": round(total_cost, 6),
            "total_cache_read_tokens": total_cache_read,
            "total_cache_creation_tokens": total_cache_creation,
            "by_purpose": by_purpose,
            "by_model": by_model,
            "by_scan": by_scan,
            "calls": [
                {
                    "timestamp": c.timestamp,
                    "model": c.model,
                    "purpose": c.purpose,
                    "scan_id": c.scan_id,
                    "input_tokens": c.input_tokens,
                    "output_tokens": c.output_tokens,
                    "total_tokens": c.total_tokens,
                    "cost_usd": c.cost_usd,
                    "duration_ms": c.duration_ms,
                    "cache_read_tokens": c.cache_read_tokens,
                    "cache_creation_tokens": c.cache_creation_tokens,
                }
                for c in calls
            ],
        }

    def reset(self) -> None:
        """Clear all recorded calls (in memory AND on disk)."""
        with self._lock:
            self.calls.clear()
            self._save()


def _create_tracker() -> UsageTracker:
    """Create the global tracker and load persisted history."""
    tracker = UsageTracker()
    tracker._load()
    return tracker


# Global singleton — loads previous history on import
usage = _create_tracker()
