"""Base analyzer interface."""

from __future__ import annotations
from abc import ABC, abstractmethod
from models import Finding


class BaseAnalyzer(ABC):
    """Base class for all static and agentic analyzers."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    def analyze(self, url: str, html: str) -> list[Finding]:
        """Analyze HTML content and return findings.

        Args:
            url: The URL of the page being analyzed.
            html: Raw HTML content of the page.

        Returns:
            List of Finding objects.
        """
        ...

    def analyze_text(self, url: str, text: str) -> list[Finding]:
        """Analyze plain text content (e.g., from agentic files).

        Default falls back to analyze() but subclasses can override
        for text-specific logic.
        """
        return self.analyze(url, text)
