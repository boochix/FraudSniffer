from __future__ import annotations

from collections import Counter
import logging
from pathlib import Path
from statistics import median
from typing import Any, Dict, List


PDF_FONT_TRIGGER_SCORE = 0.12
PDF_OBJECT_TRIGGER_SCORE = 0.12
logger = logging.getLogger(__name__)


def detect_pdf_type(document_path: Path | str) -> str:
    """Classify a PDF as DIGITAL, SCANNED, or IMAGE before OCR runs.

    - DIGITAL: Has embedded text layer (native PDF with selectable text)
    - SCANNED: PDF containing rendered page images with no/minimal text layer
    - IMAGE: Non-PDF image file (jpg, png, tiff, etc.)

    This classification drives downstream threshold relaxation so that
    scanned documents are not penalized for OCR artifacts.
    """
    path = Path(document_path)
    suffix = path.suffix.lower()

    # Non-PDF image files
    if suffix in {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".webp"}:
        return "IMAGE"

    if suffix != ".pdf":
        return "DIGITAL"  # Default for unknown formats

    try:
        import fitz  # type: ignore
    except Exception:
        return "DIGITAL"  # Can't determine without PyMuPDF, assume digital

    try:
        doc = fitz.open(str(path))
    except Exception:
        return "DIGITAL"

    total_text_chars = 0
    total_images = 0
    num_pages = min(len(doc), 3)  # Sample first 3 pages

    for page_index in range(num_pages):
        try:
            page = doc[page_index]
            text = page.get_text().strip()
            total_text_chars += len(text)
            image_list = page.get_images(full=True)
            total_images += len(image_list)
        except Exception:
            continue

    doc.close()

    # Heuristic: if very little text but images present, it's a scan
    if total_text_chars < 50 and total_images > 0:
        return "SCANNED"
    elif total_text_chars < 50 and total_images == 0:
        return "SCANNED"  # Empty PDF, treat as scanned
    else:
        return "DIGITAL"


def _color_rgb(color: int | None) -> tuple[int, int, int]:
    value = int(color or 0)
    return (value >> 16) & 255, (value >> 8) & 255, value & 255


def _is_hidden_span(span: Dict[str, Any]) -> bool:
    text = str(span.get("text") or "").strip()
    if not text:
        return False
    size = float(span.get("size") or 0)
    r, g, b = _color_rgb(span.get("color"))
    is_white = r >= 245 and g >= 245 and b >= 245
    is_tiny = 0 < size <= 1.0
    return is_white or is_tiny


def analyze_pdf_forensics(document_path: Path | str, max_pages: int = 3) -> Dict[str, Any]:
    """Inspect PDF text spans, font consistency, hidden text, and object hints."""
    path = Path(document_path)
    if path.suffix.lower() != ".pdf":
        return {
            "status": "SKIPPED",
            "pages": [],
            "font_audit": {"triggered": False, "score": 0.0, "anomalies": []},
            "object_audit": {"triggered": False, "score": 0.0, "anomalies": []},
            "hidden_text_spans": [],
            "raw_text": "",
            "visible_text": "",
        }

    try:
        import fitz  # type: ignore
    except Exception:
        return {
            "status": "UNAVAILABLE",
            "pages": [],
            "font_audit": {"triggered": False, "score": 0.0, "anomalies": []},
            "object_audit": {"triggered": False, "score": 0.0, "anomalies": ["PyMuPDF unavailable."]},
            "hidden_text_spans": [],
            "raw_text": "",
            "visible_text": "",
        }

    try:
        doc = fitz.open(str(path))
    except Exception as exc:
        return {
            "status": "UNAVAILABLE",
            "pages": [],
            "font_audit": {"triggered": False, "score": 0.0, "anomalies": []},
            "object_audit": {"triggered": False, "score": 0.0, "anomalies": [str(exc)]},
            "hidden_text_spans": [],
            "raw_text": "",
            "visible_text": "",
        }

    if doc.is_encrypted:
        doc.close()
        return {
            "status": "UNAVAILABLE",
            "pages": [],
            "font_audit": {"triggered": False, "score": 0.0, "anomalies": []},
            "object_audit": {
                "triggered": False,
                "score": 0.0,
                "anomalies": ["PDF is encrypted or password-protected; object and text forensics were skipped."],
            },
            "hidden_text_spans": [],
            "raw_text": "",
            "visible_text": "",
        }

    spans: List[Dict[str, Any]] = []
    raw_chunks: List[str] = []
    visible_chunks: List[str] = []
    hidden_spans: List[Dict[str, Any]] = []
    page_properties: List[Dict[str, Any]] = []
    object_anomalies: List[str] = []

    for page_index in range(min(len(doc), max_pages)):
        try:
            page = doc[page_index]
            rect = page.rect
            page_properties.append(
                {
                    "page": page_index + 1,
                    "width": round(float(rect.width), 2),
                    "height": round(float(rect.height), 2),
                }
            )
            page_dict = page.get_text("dict")
            for block in page_dict.get("blocks", []):
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        text = str(span.get("text") or "")
                        if not text.strip():
                            continue
                        record = {
                            "page": page_index + 1,
                            "text": text.strip(),
                            "font": str(span.get("font") or ""),
                            "size": round(float(span.get("size") or 0), 2),
                            "color": int(span.get("color") or 0),
                            "bbox": [round(float(v), 2) for v in span.get("bbox", [])],
                        }
                        spans.append(record)
                        raw_chunks.append(text)
                        if _is_hidden_span(span):
                            hidden_spans.append(record)
                        else:
                            visible_chunks.append(text)
        except Exception as exc:
            message = f"Page {page_index + 1} could not be read for PDF forensics: {exc}"
            logger.warning(message)
            object_anomalies.append(message)

    font_counter = Counter(span["font"] for span in spans if span["font"])
    dominant_font = font_counter.most_common(1)[0][0] if font_counter else ""
    sizes = [span["size"] for span in spans if span["size"] > 0]
    median_size = median(sizes) if sizes else 0
    font_anomalies = []
    suspicious_terms = ("salary", "net", "gross", "pay", "rs", "inr")

    for span in spans:
        text_lower = span["text"].lower()
        has_money_or_digits = any(ch.isdigit() for ch in span["text"]) or any(
            term in text_lower for term in suspicious_terms
        )
        font_mismatch = dominant_font and span["font"] != dominant_font
        size_mismatch = median_size and abs(span["size"] - median_size) >= 2.0
        if has_money_or_digits and (font_mismatch or size_mismatch):
            font_anomalies.append(
                {
                    "page": span["page"],
                    "text": span["text"][:80],
                    "font": span["font"],
                    "dominant_font": dominant_font,
                    "size": span["size"],
                    "median_size": round(float(median_size), 2),
                    "bbox": span["bbox"],
                }
            )

    font_score = min(0.25, 0.12 + 0.04 * (len(font_anomalies) - 1)) if font_anomalies else 0.0

    metadata = doc.metadata or {}
    producer = str(metadata.get("producer") or metadata.get("creator") or "")
    risky_producers = ("nitro", "pdfescape", "ilovepdf", "smallpdf", "sejda", "canva")
    if any(name in producer.lower() for name in risky_producers):
        object_anomalies.append(f"PDF producer/creator suggests editing software: {producer}")

    try:
        xref_per_page = doc.xref_length() / max(len(doc), 1)
        if xref_per_page > 120:
            object_anomalies.append(f"High object density: {xref_per_page:.1f} xref objects per page.")
    except Exception:
        pass

    doc.close()

    object_score = min(0.25, 0.12 + 0.04 * (len(object_anomalies) - 1)) if object_anomalies else 0.0
    return {
        "status": "REAL",
        "pages": page_properties,
        "font_audit": {
            "triggered": font_score >= PDF_FONT_TRIGGER_SCORE,
            "score": round(float(font_score), 4),
            "dominant_font": dominant_font,
            "median_size": round(float(median_size), 2) if median_size else None,
            "anomalies": font_anomalies[:12],
        },
        "object_audit": {
            "triggered": object_score >= PDF_OBJECT_TRIGGER_SCORE,
            "score": round(float(object_score), 4),
            "anomalies": object_anomalies,
            "producer": producer,
        },
        "hidden_text_spans": hidden_spans[:20],
        "raw_text": "\n".join(raw_chunks),
        "visible_text": "\n".join(visible_chunks),
    }
