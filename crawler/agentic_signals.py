"""Scanner for agentic signal files (Claude.md, Agents.md, etc.)."""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urljoin

import httpx

from config import settings
from models import AgenticFile, Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)


class AgenticSignalScanner:
    """Probes target for known agentic configuration/instruction files."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    async def scan(self) -> list[AgenticFile]:
        """Check for all known agentic signal files."""
        found: list[AgenticFile] = []

        async with httpx.AsyncClient(
            timeout=settings.request_timeout,
            follow_redirects=True,
            headers={"User-Agent": settings.user_agent},
            verify=False,
        ) as client:
            tasks = [
                self._check_file(client, filename)
                for filename in settings.agentic_files
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, AgenticFile):
                found.append(result)
            elif isinstance(result, Exception):
                logger.debug(f"Agentic signal check error: {result}")

        return found

    async def _check_file(
        self, client: httpx.AsyncClient, filename: str
    ) -> AgenticFile | None:
        """Check if a specific agentic file exists at the target."""
        url = urljoin(self.base_url + "/", filename)

        try:
            resp = await client.get(url)
        except Exception as e:
            logger.debug(f"Could not reach {url}: {e}")
            return None

        if resp.status_code != 200:
            return None

        content = resp.text[:100_000]

        # Only consider it a real file if it has meaningful content
        if len(content.strip()) < 10:
            return None

        logger.info(f"Agentic signal found: {url} ({len(content)} bytes)")

        af = AgenticFile(
            filename=filename,
            url=url,
            content=content,
            size=len(content),
        )

        # Basic finding for the existence of this file
        af.findings.append(Finding(
            category=FindingCategory.agentic_signal,
            severity=Severity.medium,
            title=f"Agentic instruction file discovered: {filename}",
            description=(
                f"The file '{filename}' was found at {url}. "
                "This file may contain instructions that AI agents follow, "
                "making it a potential vector for indirect prompt injection."
            ),
            evidence=content[:500],
            url=url,
            analyzer="agentic_signal_scanner",
            recommendation=(
                "Review this file for any instructions that could be exploited "
                "by attackers to manipulate AI agent behavior."
            ),
        ))

        return af
