"""Rule lifecycle manager — stores, validates, and promotes learned rules."""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import settings
from models import (
    FindingCategory, LearnedRule, RulesDB, RuleState, RuleTestCase, Severity,
)

logger = logging.getLogger(__name__)


class RuleManager:
    """Manages persistent storage and lifecycle of learned rules.

    All rules live in a single JSON file (learned_rules.json) which acts as
    the source of truth. The file is read on init and written on every mutation.
    """

    def __init__(self, rules_file: Path | None = None):
        self.rules_file = rules_file or (
            Path(settings.rules_dir) / "learned_rules.json"
        )
        self.db = self._load_db()

    # ── Persistence ───────────────────────────────────────────────────

    def _load_db(self) -> RulesDB:
        """Load rules from persistent JSON file."""
        if self.rules_file.exists():
            try:
                data = json.loads(self.rules_file.read_text())
                return RulesDB(**data)
            except Exception as e:
                logger.error(f"Failed to load rules DB: {e}")
        return RulesDB()

    def save(self) -> None:
        """Persist current state to disk."""
        try:
            self.rules_file.parent.mkdir(parents=True, exist_ok=True)
            self.db.last_updated = datetime.now(timezone.utc)
            self.rules_file.write_text(
                json.dumps(self.db.model_dump(mode="json"), indent=2, default=str)
            )
        except Exception as e:
            logger.error(f"Failed to save rules DB: {e}")

    # ── Rule Creation ─────────────────────────────────────────────────

    def add_candidate(
        self,
        regex_pattern: str,
        title: str,
        severity: Severity,
        category: FindingCategory,
        scan_id: str,
        evidence: str = "",
        source_url: str = "",
        test_cases: list[RuleTestCase] | None = None,
        confidence: float = 0.0,
        description: str = "",
        recommendation: str = "",
    ) -> LearnedRule | None:
        """Create a new candidate rule from LLM extraction.

        Returns None if a rule with the same regex+category already exists
        (in that case, the existing rule gets a confirmation bump instead).
        """
        # Validate regex
        try:
            re.compile(regex_pattern)
        except re.error as e:
            logger.warning(f"Invalid regex from LLM, skipping: {e}")
            return None

        # Dedup: if same pattern+category exists, confirm instead of duplicate
        existing = self._find_duplicate(regex_pattern, category)
        if existing:
            logger.info(
                f"Rule already exists ({existing.rule_id}), confirming instead"
            )
            self.confirm(existing.rule_id, scan_id)
            return existing

        rule = LearnedRule(
            rule_id=str(uuid.uuid4())[:12],
            regex_pattern=regex_pattern,
            title=title,
            severity=severity,
            category=category,
            state=RuleState.candidate,
            description=description,
            recommendation=recommendation,
            created_at=datetime.now(timezone.utc),
            created_from_scan_id=scan_id,
            source_url=source_url,
            source_finding_evidence=evidence[:500],
            test_cases=test_cases or [],
            confidence_score=min(1.0, max(0.0, confidence)),
        )

        # Run test cases to validate regex before storing
        if rule.test_cases:
            self._validate_test_cases(rule)

        self.db.rules.append(rule)
        self.save()
        logger.info(
            f"New candidate rule: {rule.rule_id} — {title} "
            f"(confidence={confidence:.0%})"
        )
        return rule

    def _find_duplicate(
        self, regex_pattern: str, category: FindingCategory,
    ) -> LearnedRule | None:
        """Check if a rule with the same regex+category already exists."""
        for rule in self.db.rules:
            if rule.state == RuleState.rejected:
                continue
            if (
                rule.regex_pattern == regex_pattern
                and rule.category == category
            ):
                return rule
        return None

    def _validate_test_cases(self, rule: LearnedRule) -> None:
        """Run test cases against the regex pattern, log failures."""
        try:
            pattern = re.compile(rule.regex_pattern, re.IGNORECASE)
        except re.error:
            return

        for tc in rule.test_cases:
            match = pattern.search(tc.text)
            if tc.should_match and not match:
                logger.warning(
                    f"Rule {rule.rule_id}: positive test case FAILED — "
                    f"pattern did not match: {tc.text[:80]}"
                )
            elif not tc.should_match and match:
                logger.warning(
                    f"Rule {rule.rule_id}: negative test case FAILED — "
                    f"pattern matched when it shouldn't: {tc.text[:80]}"
                )

    # ── Lifecycle Management ──────────────────────────────────────────

    def promote(self, rule_id: str, target_state: RuleState) -> LearnedRule:
        """Promote a rule to a new state (manual review workflow)."""
        rule = self.get_rule(rule_id)
        if not rule:
            raise ValueError(f"Rule {rule_id} not found")

        valid_transitions = {
            RuleState.candidate: {RuleState.validated, RuleState.active, RuleState.rejected},
            RuleState.validated: {RuleState.active, RuleState.rejected},
            RuleState.active: {RuleState.rejected},
            RuleState.rejected: {RuleState.candidate},  # allow un-reject
        }

        allowed = valid_transitions.get(rule.state, set())
        if target_state not in allowed:
            raise ValueError(
                f"Cannot transition {rule.state.value} → {target_state.value}"
            )

        rule.state = target_state
        self.save()
        logger.info(f"Rule {rule_id} promoted to {target_state.value}")
        return rule

    def reject(self, rule_id: str) -> None:
        """Mark rule as rejected."""
        rule = self.get_rule(rule_id)
        if rule:
            rule.state = RuleState.rejected
            self.save()
            logger.info(f"Rule {rule_id} rejected")

    def delete(self, rule_id: str) -> bool:
        """Hard-delete a rule."""
        before = len(self.db.rules)
        self.db.rules = [r for r in self.db.rules if r.rule_id != rule_id]
        if len(self.db.rules) < before:
            self.save()
            return True
        return False

    def confirm(self, rule_id: str, scan_id: str) -> LearnedRule | None:
        """Record that this rule matched in a new scan (re-confirmation).

        This builds validation evidence. If auto-promote is enabled and
        the threshold is met, the rule is automatically promoted to active.
        """
        rule = self.get_rule(rule_id)
        if not rule:
            return None

        if scan_id not in rule.confirmed_scan_ids:
            rule.confirmed_scan_ids.append(scan_id)
            rule.validation_count += 1
            rule.last_confirmed_at = datetime.now(timezone.utc)
            rule.true_positive_count += 1

            # Auto-promote check
            if self._should_auto_promote(rule):
                logger.info(
                    f"Rule {rule_id} auto-promoted to active "
                    f"(validations={rule.validation_count})"
                )
                rule.state = RuleState.active

            self.save()

        return rule

    def _should_auto_promote(self, rule: LearnedRule) -> bool:
        """Check if rule meets auto-promotion criteria."""
        threshold = settings.rule_auto_promote_threshold
        if threshold <= 0:
            return False  # Manual mode
        return (
            rule.state in (RuleState.candidate, RuleState.validated)
            and rule.validation_count >= threshold
            and rule.confidence_score >= settings.rule_min_confidence
            and rule.false_positive_count == 0
        )

    # ── Queries ───────────────────────────────────────────────────────

    def get_rule(self, rule_id: str) -> LearnedRule | None:
        for rule in self.db.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def get_rules_by_state(self, state: RuleState) -> list[LearnedRule]:
        return [r for r in self.db.rules if r.state == state]

    def get_active_rules(self) -> list[LearnedRule]:
        return self.get_rules_by_state(RuleState.active)

    def stats(self) -> dict:
        """High-level statistics about the rule database."""
        by_state = {}
        for s in RuleState:
            by_state[s.value] = len(self.get_rules_by_state(s))

        return {
            "total_rules": len(self.db.rules),
            **by_state,
            "avg_confidence": (
                sum(r.confidence_score for r in self.db.rules) / len(self.db.rules)
                if self.db.rules else 0.0
            ),
            "last_updated": (
                self.db.last_updated.isoformat() if self.db.last_updated else None
            ),
        }

    # ── Rule Testing ──────────────────────────────────────────────────

    @staticmethod
    def test_rule(regex_pattern: str, test_string: str) -> dict:
        """Test a regex pattern against a string. Returns match info."""
        try:
            pattern = re.compile(regex_pattern, re.IGNORECASE)
            match = pattern.search(test_string)
            return {
                "matched": bool(match),
                "match_text": match.group(0) if match else None,
                "match_start": match.start() if match else None,
                "match_end": match.end() if match else None,
            }
        except re.error as e:
            return {"error": str(e), "matched": False}
