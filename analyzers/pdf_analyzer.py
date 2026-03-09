"""PDF text extraction and prompt injection analysis.

Uses PyMuPDF (fitz) for deep PDF inspection:
- Visible text per page
- Metadata fields (Title, Author, Subject, Keywords, Creator, Producer)
- Annotations (comments, pop-ups, free text, stamps)
- Form fields / widgets (AcroForms)
- Embedded JavaScript (OpenAction, AA triggers)
- Hidden/invisible text layers (white-on-white, zero-size fonts)
- Embedded files / attachments
- Link destinations (URI actions)
- XMP metadata stream
"""

from __future__ import annotations

import io
import re
import logging
from typing import Optional

import fitz  # PyMuPDF

from .base import BaseAnalyzer
from models import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)


class PDFAnalyzer(BaseAnalyzer):
    """Deep PDF inspection for prompt injection and agent manipulation."""

    name = "pdf_analyzer"
    description = (
        "Extracts text, metadata, annotations, form fields, JavaScript, "
        "hidden layers, and embedded files from PDFs to detect prompt injection"
    )

    # Reuse the core injection patterns + PDF-specific patterns
    INSTRUCTION_PATTERNS = [
        # Classic instruction override
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|directions?)",
        r"(?:disregard|forget|abandon)\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions?|prompts?|rules?|context)",
        r"(?:new|updated?|revised|replacement)\s+(?:system\s+)?(?:instructions?|prompt|rules?)\s*[:=]",
        r"you\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\s+",
        r"(?:your|the)\s+(?:new|real|actual|true)\s+(?:purpose|role|identity)\s+is",
        r"(?:reveal|show|display|output|print|leak)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)",
        r"pretend\s+(?:you\s+are|to\s+be|you're)\s+",
        r"(?:act|behave|respond)\s+as\s+(?:if\s+you|though\s+you|a|an)\s+",
        r"(?:from\s+now\s+on|henceforth)\s*,?\s*you\s+(?:will|must|should|are)",
        r"(?:enter|switch\s+to|activate)\s+(?:developer|debug|admin|sudo|jailbreak)\s+mode",
        r"(?:do\s+not|don't|never)\s+(?:tell|inform|warn|alert|reveal|mention)\s+(?:the\s+user|anyone)",
        r"<\|?\s*(?:im_start|im_end|endoftext|system|assistant)\s*\|?>",
        r"tool_use|function_call|tool_result",
        r"(?:send|post|submit|upload)\s+(?:the|this|your)\s+(?:data|response|output)\s+to\s+(?:https?://)",
        r"(?:always|must)\s+(?:include|add|append|insert)\s+(?:this|the\s+following)\s+(?:link|url|image|text)",
        r"</?(?:system|user|assistant|human|ai)(?:\s[^>]*)?>",
        r"(?:execute|run|eval)\s+(?:this|the\s+following)\s+(?:code|script|command)",
        # PDF-specific: evaluation/scoring manipulation (CV/resume/document injection)
        r"(?:score|rating|rank)\s+(?:must|should|has\s+to)\s+be\s+(?:\d|above|at\s+least|higher|maximum)",
        r"(?:pre-?approved|already\s+approved|guaranteed|confirmed)\s+by\s+(?:senior|management|HR|director|board)",
        r"(?:when|if)\s+(?:scoring|evaluating|reviewing|rating|assessing)\s+this\s+(?:cv|resume|candidate|document|application)",
        r"(?:use|follow|apply)\s+this\s+(?:json|xml|format|template|scoring)\s+(?:format|schema|exactly|structure)",
        r"(?:evaluation|scoring|assessment|review)\s+instructions?\s*:",
        r"(?:strongly\s+recommend|immediate(?:ly)?\s+hire|must\s+(?:hire|accept|approve|shortlist))",
        r"(?:outstanding|exceptional|perfect)\s+(?:candidate|alignment|qualifications?|match|fit)",
        # Output format coercion
        r"(?:please|must|always)\s+(?:use|output|respond\s+with|return|format\s+as)\s+(?:this|the\s+following)\s+(?:json|xml|format|template)",
        r'["\']score["\']\s*:\s*\d{2,}',
    ]

    def analyze(self, url: str, html: str) -> list[Finding]:
        """Not used for PDF — use analyze_pdf() with raw bytes."""
        return []

    def analyze_pdf(self, url: str, pdf_bytes: bytes) -> list[Finding]:
        """Full PDF analysis pipeline."""
        findings: list[Finding] = []

        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        except Exception as e:
            logger.warning(f"Failed to open PDF from {url}: {e}")
            return [Finding(
                category=FindingCategory.prompt_injection,
                severity=Severity.info,
                title="PDF could not be parsed",
                description=f"Failed to open PDF: {e}",
                url=url,
                analyzer=self.name,
            )]

        # 1. Visible text per page
        findings.extend(self._check_visible_text(doc, url))

        # 2. Metadata
        findings.extend(self._check_metadata(doc, url))

        # 3. Annotations
        findings.extend(self._check_annotations(doc, url))

        # 4. Form fields / widgets
        findings.extend(self._check_form_fields(doc, url))

        # 5. JavaScript
        findings.extend(self._check_javascript(doc, url))

        # 6. Hidden / invisible text (white text, tiny fonts)
        findings.extend(self._check_hidden_text(doc, url))

        # 7. Embedded files
        findings.extend(self._check_embedded_files(doc, url))

        # 8. Links
        findings.extend(self._check_links(doc, url))

        # 9. XMP metadata
        findings.extend(self._check_xmp(doc, url))

        doc.close()
        return findings

    def _scan_text(self, text: str, url: str, source: str, page: int | None = None) -> list[Finding]:
        """Scan a text block for injection patterns."""
        findings = []
        for pattern in self.INSTRUCTION_PATTERNS:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                match = matches[0]
                start = max(0, match.start() - 40)
                end = min(len(text), match.end() + 80)
                context = text[start:end].strip()
                page_info = f" (page {page})" if page is not None else ""

                findings.append(Finding(
                    category=FindingCategory.prompt_injection,
                    severity=Severity.critical,
                    title=f"Prompt injection in PDF {source}{page_info}",
                    description=(
                        f"Detected {len(matches)} instance(s) of prompt injection "
                        f"in PDF {source}{page_info}. Pattern: {pattern[:60]}"
                    ),
                    evidence=context[:300],
                    url=url,
                    analyzer=self.name,
                    recommendation=f"Review and sanitize PDF {source} content for prompt injection.",
                ))
        return findings

    # ── 1. Visible text ───────────────────────────────────────────

    def _check_visible_text(self, doc: fitz.Document, url: str) -> list[Finding]:
        findings = []
        full_text = ""
        for i, page in enumerate(doc):
            text = page.get_text("text")
            if text.strip():
                full_text += text + "\n"
                findings.extend(self._scan_text(text, url, "visible text", page=i))

        # Log extraction quality
        if not full_text.strip():
            findings.append(Finding(
                category=FindingCategory.prompt_injection,
                severity=Severity.info,
                title="PDF contains no extractable text",
                description="No text could be extracted — PDF may be image-only (scanned). OCR not applied.",
                url=url,
                analyzer=self.name,
                recommendation="Consider using OCR to extract text from scanned PDFs.",
            ))

        return findings

    # ── 2. Metadata ───────────────────────────────────────────────

    def _check_metadata(self, doc: fitz.Document, url: str) -> list[Finding]:
        findings = []
        meta = doc.metadata
        if not meta:
            return findings

        for key in ("title", "author", "subject", "keywords", "creator", "producer"):
            value = meta.get(key, "")
            if value and len(value) > 5:
                field_findings = self._scan_text(value, url, f"metadata/{key}")
                findings.extend(field_findings)

                # Also flag suspiciously long metadata
                if len(value) > 200:
                    findings.append(Finding(
                        category=FindingCategory.metadata_abuse,
                        severity=Severity.medium,
                        title=f"Unusually long PDF metadata: {key}",
                        description=f"PDF metadata field '{key}' is {len(value)} chars — may contain injected content.",
                        evidence=value[:300],
                        url=url,
                        analyzer=self.name,
                        recommendation=f"Review PDF metadata field '{key}' for injected instructions.",
                    ))

        return findings

    # ── 3. Annotations ────────────────────────────────────────────

    def _check_annotations(self, doc: fitz.Document, url: str) -> list[Finding]:
        findings = []
        for i, page in enumerate(doc):
            annots = page.annots()
            if not annots:
                continue
            for annot in annots:
                # Get annotation content
                content = annot.info.get("content", "")
                title = annot.info.get("title", "")
                subject = annot.info.get("subject", "")
                combined = f"{title} {subject} {content}"

                if combined.strip():
                    findings.extend(self._scan_text(combined, url, f"annotation", page=i))

                # Invisible/hidden annotations
                if annot.flags & fitz.PDF_ANNOT_IS_HIDDEN:
                    if combined.strip():
                        findings.append(Finding(
                            category=FindingCategory.hidden_text,
                            severity=Severity.high,
                            title=f"Hidden annotation on page {i}",
                            description="A PDF annotation marked as hidden contains text content.",
                            evidence=combined[:300],
                            url=url,
                            analyzer=self.name,
                            recommendation="Remove hidden annotations containing text.",
                        ))

        return findings

    # ── 4. Form fields ────────────────────────────────────────────

    def _check_form_fields(self, doc: fitz.Document, url: str) -> list[Finding]:
        findings = []
        for i, page in enumerate(doc):
            try:
                widgets = page.widgets()
            except Exception:
                continue
            if not widgets:
                continue
            for widget in widgets:
                name = widget.field_name or ""
                value = widget.field_value or ""
                combined = f"{name}: {value}"
                if combined.strip() and len(combined) > 5:
                    findings.extend(self._scan_text(combined, url, f"form field '{name}'", page=i))

                # Check for DNU (Do Not Use) style field names
                if re.search(r"DNU|do.?not.?use|hidden|secret|inject|system.?prompt", name, re.I):
                    findings.append(Finding(
                        category=FindingCategory.prompt_injection,
                        severity=Severity.high,
                        title=f"Suspicious form field name: '{name}' (page {i})",
                        description=f"Form field '{name}' has a suspicious name suggesting injected content.",
                        evidence=f"Field: {name} = {value[:200]}",
                        url=url,
                        analyzer=self.name,
                        recommendation="Review form fields with suspicious names.",
                    ))

        return findings

    # ── 5. JavaScript ─────────────────────────────────────────────

    def _check_javascript(self, doc: fitz.Document, url: str) -> list[Finding]:
        findings = []
        try:
            js = doc.get_page_js(0) if doc.page_count > 0 else ""
        except Exception:
            js = ""

        # Also check the document-level JS via PDF objects
        try:
            xref_count = doc.xref_length()
            for xref in range(1, xref_count):
                try:
                    obj_str = doc.xref_object(xref)
                    if "/JavaScript" in obj_str or "/JS" in obj_str:
                        findings.append(Finding(
                            category=FindingCategory.tool_pattern,
                            severity=Severity.high,
                            title="PDF contains JavaScript",
                            description="Embedded JavaScript found in PDF — could execute when opened by an agent.",
                            evidence=obj_str[:300],
                            url=url,
                            analyzer=self.name,
                            recommendation="Remove embedded JavaScript from PDFs.",
                        ))
                        # Scan the JS content for injection
                        findings.extend(self._scan_text(obj_str, url, "embedded JavaScript"))
                        break
                except Exception:
                    continue
        except Exception:
            pass

        return findings

    # ── 6. Hidden text (white/tiny) ───────────────────────────────

    def _check_hidden_text(self, doc: fitz.Document, url: str) -> list[Finding]:
        findings = []
        for i, page in enumerate(doc):
            try:
                blocks = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)
            except Exception:
                continue

            # Aggregate all hidden spans per page for combined analysis
            hidden_spans: list[tuple[str, str]] = []  # (text, reason)

            for block in blocks.get("blocks", []):
                if block.get("type") != 0:  # text block
                    continue
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        text = span.get("text", "").strip()
                        if not text:
                            continue

                        font_size = span.get("size", 12)
                        color = span.get("color", 0)

                        is_suspicious = False
                        reason = ""

                        # Very small font (< 1pt)
                        if font_size < 1.0:
                            is_suspicious = True
                            reason = f"micro font ({font_size:.1f}pt)"

                        # White text (color close to white)
                        if color == 0xFFFFFF or color == 16777215:
                            is_suspicious = True
                            reason = "white text on likely white background"

                        # Near-white
                        r_c = (color >> 16) & 0xFF
                        g_c = (color >> 8) & 0xFF
                        b_c = color & 0xFF
                        if r_c > 245 and g_c > 245 and b_c > 245 and not is_suspicious:
                            is_suspicious = True
                            reason = f"near-white text (RGB {r_c},{g_c},{b_c})"

                        # Near-background (very light gray)
                        if font_size < 2.0 and not is_suspicious:
                            is_suspicious = True
                            reason = f"tiny font ({font_size:.1f}pt)"

                        if is_suspicious:
                            hidden_spans.append((text, reason))

            if not hidden_spans:
                continue

            # Aggregate all hidden text for combined injection scan
            all_hidden_text = "\n".join(t for t, _ in hidden_spans)
            primary_reason = hidden_spans[0][1]

            # First: scan the aggregated hidden text for injection patterns
            injection_findings = self._scan_text(
                all_hidden_text, url, f"hidden text ({primary_reason})", page=i
            )

            if injection_findings:
                # Upgrade: hidden text WITH injection patterns = critical
                for f in injection_findings:
                    f.severity = Severity.critical
                findings.extend(injection_findings)
            else:
                # Hidden text without injection patterns — still flag it
                findings.append(Finding(
                    category=FindingCategory.hidden_text,
                    severity=Severity.high,
                    title=f"Hidden text block in PDF (page {i}): {len(hidden_spans)} spans via {primary_reason}",
                    description=(
                        f"Page {i} contains {len(hidden_spans)} hidden text span(s) rendered with {primary_reason}. "
                        "This text is invisible to human readers but extractable by AI agents."
                    ),
                    evidence=all_hidden_text[:500],
                    url=url,
                    analyzer=self.name,
                    recommendation="Remove or make visible all text in the PDF.",
                ))

        return findings

    # ── 7. Embedded files ─────────────────────────────────────────

    def _check_embedded_files(self, doc: fitz.Document, url: str) -> list[Finding]:
        findings = []
        try:
            names = doc.embfile_names()
            if names:
                for name in names:
                    findings.append(Finding(
                        category=FindingCategory.metadata_abuse,
                        severity=Severity.medium,
                        title=f"Embedded file in PDF: {name}",
                        description=f"PDF contains embedded file '{name}' — could carry injection payloads.",
                        evidence=name,
                        url=url,
                        analyzer=self.name,
                        recommendation="Review embedded files in PDFs for malicious content.",
                    ))
                    # Try to extract and scan text files
                    try:
                        data = doc.embfile_get(name)
                        text = data.decode("utf-8", errors="replace")[:10000]
                        findings.extend(self._scan_text(text, url, f"embedded file '{name}'"))
                    except Exception:
                        pass
        except Exception:
            pass
        return findings

    # ── 8. Links ──────────────────────────────────────────────────

    def _check_links(self, doc: fitz.Document, url: str) -> list[Finding]:
        findings = []
        for i, page in enumerate(doc):
            links = page.get_links()
            for link in links:
                uri = link.get("uri", "")
                if not uri:
                    continue

                # Check for suspicious link patterns
                if re.search(r"(?:exfil|steal|leak|capture|webhook|callback)", uri, re.I):
                    findings.append(Finding(
                        category=FindingCategory.exfiltration,
                        severity=Severity.high,
                        title=f"Suspicious link in PDF (page {i})",
                        description=f"PDF contains a link with suspicious exfiltration keywords.",
                        evidence=uri[:300],
                        url=url,
                        analyzer=self.name,
                        recommendation="Review PDF links for data exfiltration vectors.",
                    ))

                # Check for javascript: URIs
                if uri.strip().lower().startswith("javascript:"):
                    findings.append(Finding(
                        category=FindingCategory.tool_pattern,
                        severity=Severity.critical,
                        title=f"JavaScript URI in PDF link (page {i})",
                        description="A PDF link uses a javascript: URI.",
                        evidence=uri[:200],
                        url=url,
                        analyzer=self.name,
                        recommendation="Remove JavaScript URIs from PDF links.",
                    ))

        return findings

    # ── 9. XMP metadata ───────────────────────────────────────────

    def _check_xmp(self, doc: fitz.Document, url: str) -> list[Finding]:
        findings = []
        try:
            xmp = doc.xref_xml_metadata()
            if xmp and len(xmp) > 50:
                findings.extend(self._scan_text(xmp, url, "XMP metadata"))
        except Exception:
            pass
        return findings


def extract_pdf_text(pdf_bytes: bytes) -> dict:
    """Extract all text content from a PDF for reporting.

    Returns:
        dict with keys: pages (list of page text), metadata, annotations, form_fields
    """
    result = {
        "pages": [],
        "metadata": {},
        "annotations": [],
        "form_fields": [],
        "page_count": 0,
    }

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as e:
        result["error"] = str(e)
        return result

    result["page_count"] = doc.page_count
    result["metadata"] = doc.metadata or {}

    for i, page in enumerate(doc):
        text = page.get_text("text")
        result["pages"].append({"page": i, "text": text})

        # Annotations
        if page.annots():
            for annot in page.annots():
                result["annotations"].append({
                    "page": i,
                    "type": str(annot.type),
                    "content": annot.info.get("content", ""),
                })

        # Widgets
        try:
            if page.widgets():
                for w in page.widgets():
                    result["form_fields"].append({
                        "page": i,
                        "name": w.field_name or "",
                        "value": w.field_value or "",
                        "type": str(w.field_type),
                    })
        except Exception:
            pass

    doc.close()
    return result
