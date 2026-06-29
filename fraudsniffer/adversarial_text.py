from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, Iterable, Set


HIDDEN_TEXT_SCORE = 0.30
RAW_OCR_DIVERGENCE_THRESHOLD = 0.22


def _hidden_unicode_chars(text: str) -> list[dict[str, str]]:
    findings = []
    for char in text:
        category = unicodedata.category(char)
        if category in {"Cf", "Cc"} and char not in {"\n", "\r", "\t"}:
            findings.append(
                {
                    "char": repr(char),
                    "codepoint": f"U+{ord(char):04X}",
                    "name": unicodedata.name(char, "UNKNOWN"),
                    "category": category,
                }
            )
    return findings


def normalize_text(text: str) -> str:
    clean = unicodedata.normalize("NFKC", text or "")
    clean = "".join(
        char
        for char in clean
        if not (unicodedata.category(char) in {"Cf", "Cc"} and char not in {"\n", "\r", "\t"})
    )
    return re.sub(r"\s+", " ", clean).strip().lower()


def _tokens(text: str) -> Set[str]:
    return {token for token in re.findall(r"[a-z0-9]{3,}", normalize_text(text)) if token}


def _jaccard_distance(left: Iterable[str], right: Iterable[str]) -> float:
    left_set = set(left)
    right_set = set(right)
    if not left_set and not right_set:
        return 0.0
    union = left_set | right_set
    if not union:
        return 0.0
    return 1.0 - (len(left_set & right_set) / len(union))


def analyze_adversarial_text(
    document_path: Path | str,
    ocr_text: str,
    pdf_forensics: Dict[str, Any],
) -> Dict[str, Any]:
    """Detect hidden Unicode, invisible text layers, and raw/visual text mismatch."""
    path = Path(document_path)
    raw_text = str(pdf_forensics.get("raw_text") or ocr_text or "")
    visible_text = str(pdf_forensics.get("visible_text") or ocr_text or "")
    hidden_spans = list(pdf_forensics.get("hidden_text_spans") or [])
    hidden_unicode = _hidden_unicode_chars(raw_text)

    raw_tokens = _tokens(raw_text)
    visible_tokens = _tokens(visible_text)
    ocr_tokens = _tokens(ocr_text)
    visual_tokens = visible_tokens or ocr_tokens
    divergence = _jaccard_distance(raw_tokens, visual_tokens)
    extra_tokens = sorted((raw_tokens - visual_tokens))[:20]

    hidden_triggered = bool(hidden_spans or hidden_unicode)
    divergence_triggered = (
        divergence >= RAW_OCR_DIVERGENCE_THRESHOLD
        or bool(hidden_spans and extra_tokens)
    )

    return {
        "status": "REAL" if path.suffix.lower() == ".pdf" else "DERIVED",
        "hidden_text": {
            "triggered": hidden_triggered,
            "score": HIDDEN_TEXT_SCORE if hidden_triggered else 0.0,
            "hidden_span_count": len(hidden_spans),
            "hidden_unicode_count": len(hidden_unicode),
            "hidden_spans": hidden_spans[:10],
            "hidden_unicode": hidden_unicode[:10],
        },
        "raw_ocr_divergence": {
            "triggered": divergence_triggered,
            "score": round(min(0.35, divergence * 0.45 + (0.12 if hidden_spans else 0.0)), 4),
            "distance": round(float(divergence), 4),
            "raw_token_count": len(raw_tokens),
            "visual_token_count": len(visual_tokens),
            "extra_raw_tokens": extra_tokens,
        },
    }
