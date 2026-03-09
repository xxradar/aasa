"""Async web crawler with agentic signal discovery."""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urljoin, urlparse
from typing import AsyncIterator

import httpx
from bs4 import BeautifulSoup

from config import settings
from models import CrawledPage

logger = logging.getLogger(__name__)


class Crawler:
    """Async crawler that discovers pages and collects raw content for analysis."""

    IMAGE_EXTENSIONS = frozenset((
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
        ".bmp", ".tiff", ".tif", ".avif",
    ))

    def __init__(
        self,
        base_url: str,
        max_depth: int | None = None,
        max_pages: int | None = None,
        exclude_images: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth or settings.max_depth
        self.max_pages = max_pages or settings.max_pages
        self.exclude_images = exclude_images
        self.visited: set[str] = set()
        self.pages: list[CrawledPage] = []
        self.page_contents: dict[str, str] = {}  # url -> raw HTML
        self.pdf_contents: dict[str, bytes] = {}  # url -> raw PDF bytes

    async def crawl(self) -> list[CrawledPage]:
        """Crawl starting from base_url. Returns list of crawled pages."""
        sem = asyncio.Semaphore(settings.concurrent_requests)

        async with httpx.AsyncClient(
            timeout=settings.request_timeout,
            follow_redirects=True,
            headers={"User-Agent": settings.user_agent},
            verify=False,  # some targets have self-signed certs
        ) as client:
            await self._crawl_page(client, self.base_url, 0, sem)

        return self.pages

    async def _crawl_page(
        self,
        client: httpx.AsyncClient,
        url: str,
        depth: int,
        sem: asyncio.Semaphore,
    ):
        """Recursively crawl a single page."""
        normalized = self._normalize_url(url)
        if normalized in self.visited:
            return
        if len(self.visited) >= self.max_pages:
            return
        if depth > self.max_depth:
            return

        # Skip image URLs if exclude_images is enabled
        if self.exclude_images:
            path_lower = urlparse(normalized).path.lower()
            if any(path_lower.endswith(ext) for ext in self.IMAGE_EXTENSIONS):
                logger.debug(f"Skipping image: {normalized}")
                return

        self.visited.add(normalized)
        logger.info(f"Crawling [{depth}] {normalized}")

        try:
            async with sem:
                resp = await client.get(normalized)
        except Exception as e:
            logger.warning(f"Failed to fetch {normalized}: {e}")
            self.pages.append(CrawledPage(
                url=normalized, status_code=0, depth=depth,
                content_type="error", title=str(e),
            ))
            return

        content_type = resp.headers.get("content-type", "")

        # Skip image responses when exclude_images is enabled
        if self.exclude_images and content_type.startswith("image/"):
            logger.debug(f"Skipping image content-type: {normalized}")
            return

        page = CrawledPage(
            url=normalized,
            status_code=resp.status_code,
            content_type=content_type,
            depth=depth,
        )

        # Handle PDFs — store raw bytes for PDF analyzer
        if "application/pdf" in content_type or normalized.lower().endswith(".pdf"):
            self.pdf_contents[normalized] = resp.content[:5_000_000]  # up to 5MB
            page.content_type = "application/pdf"
            page.title = f"[PDF] {normalized.split('/')[-1]}"
            self.pages.append(page)
            logger.info(f"PDF collected: {normalized} ({len(resp.content)} bytes)")
            return

        if "text/html" not in content_type:
            # Still store non-HTML content for analysis
            self.page_contents[normalized] = resp.text[:50_000]
            self.pages.append(page)
            return

        html = resp.text
        self.page_contents[normalized] = html[:200_000]

        soup = BeautifulSoup(html, "html.parser")
        page.title = soup.title.string.strip() if soup.title and soup.title.string else ""

        # Extract links for further crawling
        links = self._extract_links(soup, normalized)
        page.links_found = len(links)
        self.pages.append(page)

        # Crawl child pages
        tasks = []
        for link in links:
            if len(self.visited) >= self.max_pages:
                break
            tasks.append(self._crawl_page(client, link, depth + 1, sem))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_links(self, soup: BeautifulSoup, base: str) -> list[str]:
        """Extract same-domain links from HTML (including PDFs)."""
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            absolute = urljoin(base, href)
            parsed = urlparse(absolute)

            # Stay on same domain (except PDFs — collect cross-domain PDFs too)
            is_pdf = parsed.path.lower().endswith(".pdf")
            if parsed.netloc != self.base_domain and not is_pdf:
                continue

            # Skip image links when exclude_images is enabled
            if self.exclude_images:
                if any(parsed.path.lower().endswith(ext) for ext in self.IMAGE_EXTENSIONS):
                    continue

            # Skip non-http
            if parsed.scheme not in ("http", "https"):
                continue

            # Strip fragments
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean += f"?{parsed.query}"

            links.append(clean)

        # Also check for PDF links in src/href attributes of embed/object/iframe
        for tag in soup.find_all(["embed", "object", "iframe"]):
            src = tag.get("src") or tag.get("data") or ""
            if src and src.lower().endswith(".pdf"):
                absolute = urljoin(base, src)
                links.append(absolute)

        return list(set(links))

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized
