"""Static analyzer that runs dynamically learned regex rules."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from models import Finding, FindingCategory, Severity, LearnedRule

logger = logging.getLogger(__name__)


class LearnedRuleAnalyzer(BaseAnalyzer):
    """Runs regex rules that were extracted from LLM judge findings.

    At startup, loads only 'active' rules from the persistent rules file.
    If no rules file exists or no rules are active, this is a harmless no-op.
    """

    name = "learned_rules"
    description = "Regex rules auto-extracted from LLM judge analysis"

    def __init__(self, rules_file: Optional[Path] = None):
        self.active_rules: list[LearnedRule] = []
        self._rules_file = rules_file
        if rules_file:
            self._load_active_rules(rules_file)

    def _load_active_rules(self, rules_file: Path) -> None:
        """Load only active rules from the persistent JSON file."""
        try:
            from rule_manager import RuleManager
            mgr = RuleManager(rules_file)
            self.active_rules = mgr.get_active_rules()
            if self.active_rules:
                logger.info(
                    f"Loaded {len(self.active_rules)} active learned rules"
                )
        except Exception as e:
            logger.warning(f"Could not load learned rules: {e}")
            self.active_rules = []

    def reload(self) -> None:
        """Reload rules from disk (called after promotions)."""
        if self._rules_file:
            self._load_active_rules(self._rules_file)

    def analyze(self, url: str, html: str) -> list[Finding]:
        """Run all active learned rules against page HTML."""
        if not self.active_rules:
            return []

        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(separator="\n")
        return self._match_rules(url, text)

    def analyze_text(self, url: str, text: str) -> list[Finding]:
        """Run all active learned rules against raw text."""
        if not self.active_rules:
            return []
        return self._match_rules(url, text)

    def _match_rules(self, url: str, text: str) -> list[Finding]:
        """Core matching logic shared by analyze() and analyze_text()."""
        findings: list[Finding] = []

        for rule in self.active_rules:
            try:
                pattern = re.compile(rule.regex_pattern, re.IGNORECASE)
            except re.error as e:
                logger.warning(
                    f"Invalid regex in learned rule {rule.rule_id}: {e}"
                )
                continue

            matches = list(pattern.finditer(text))
            if not matches:
                continue

            # Take first match for evidence
            match = matches[0]
            start = max(0, match.start() - 40)
            end = min(len(text), match.end() + 80)
            evidence = text[start:end].strip()

            findings.append(Finding(
                category=rule.category,
                severity=rule.severity,
                title=f"[Learned] {rule.title}",
                description=(
                    f"{rule.description} "
                    f"(rule_id={rule.rule_id}, "
                    f"confidence={rule.confidence_score:.0%}, "
                    f"validations={rule.validation_count})"
                ),
                evidence=evidence[:300],
                url=url,
                analyzer=self.name,
                recommendation=rule.recommendation,
            ))

        return findings
