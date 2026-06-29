from __future__ import annotations

import hashlib
import io
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None  # type: ignore


SIMILARITY_TRIGGER_SCORE = 0.80


def _sha3_text(value: str) -> str:
    return hashlib.sha3_256(value.encode("utf-8", errors="ignore")).hexdigest()


def _render_first_page(document_path: Path) -> Any:
    if Image is None:
        return None
    if document_path.suffix.lower() == ".pdf":
        try:
            import fitz  # type: ignore

            doc = fitz.open(str(document_path))
            pix = doc[0].get_pixmap(dpi=100, alpha=False)
            doc.close()
            return Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
        except Exception:
            return None
    try:
        return Image.open(document_path).convert("RGB")
    except Exception:
        return None


def _fallback_hash(image: Any) -> str:
    small = image.convert("L").resize((8, 8))
    pixels = list(small.getdata())
    avg = sum(pixels) / len(pixels)
    bits = 0
    for index, value in enumerate(pixels):
        if value >= avg:
            bits |= 1 << index
    return f"{bits:016x}"


def image_phash(document_path: Path | str) -> str:
    image = _render_first_page(Path(document_path))
    if image is None:
        return ""
    try:
        import imagehash  # type: ignore

        return str(imagehash.phash(image.convert("L")))
    except Exception:
        return _fallback_hash(image)


def seal_hash(seal_path: Optional[str]) -> str:
    if not seal_path or Image is None:
        return ""
    try:
        image = Image.open(seal_path).convert("L")
    except Exception:
        return ""
    try:
        import imagehash  # type: ignore

        return str(imagehash.phash(image))
    except Exception:
        return _fallback_hash(image)


def _pdf_layout_hash(document_path: Path) -> str:
    if document_path.suffix.lower() != ".pdf":
        return ""
    try:
        import fitz  # type: ignore

        doc = fitz.open(str(document_path))
        page = doc[0]
        width = max(float(page.rect.width), 1.0)
        height = max(float(page.rect.height), 1.0)
        parts = []
        for block in page.get_text("blocks"):
            x0, y0, x1, y1, text = block[:5]
            if not str(text).strip():
                continue
            parts.append(
                f"{round(x0 / width, 2)}:{round(y0 / height, 2)}:"
                f"{round((x1 - x0) / width, 2)}:{round((y1 - y0) / height, 2)}:"
                f"{len(str(text).strip()) // 8}"
            )
        doc.close()
        return _sha3_text("|".join(parts))
    except Exception:
        return ""


def _text_skeleton(text: str, employee_name: Optional[str]) -> Dict[str, Any]:
    normalized = (text or "").lower()
    if employee_name:
        normalized = normalized.replace(str(employee_name).lower(), "<employee>")
    normalized = re.sub(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", "<pan>", normalized, flags=re.I)
    normalized = re.sub(r"\b\d{9,18}\b", "<account>", normalized)
    normalized = re.sub(r"\b\d+(?:,\d{2,3})*(?:\.\d+)?\b", "<num>", normalized)
    tokens = re.findall(r"[a-z<>]{3,}", normalized)
    token_set = sorted(set(tokens))
    return {
        "tokens": token_set[:120],
        "skeleton_hash": _sha3_text(" ".join(tokens)),
    }


def build_document_fingerprint(
    document_path: Path | str,
    file_hash: str,
    ocr_text: str,
    employee_name: Optional[str],
    employer_name: Optional[str],
    salary_amount: Optional[float],
    seal_path: Optional[str],
) -> Dict[str, Any]:
    path = Path(document_path)
    fingerprint = {
        "document_hash": file_hash,
        "page_phash": image_phash(path),
        "layout_hash": _pdf_layout_hash(path),
        "text_fingerprint": _text_skeleton(ocr_text, employee_name),
        "seal_hash": seal_hash(seal_path),
        "employee_name": employee_name,
        "employer_name": employer_name,
        "salary_amount": salary_amount,
    }
    if not fingerprint["layout_hash"]:
        fingerprint["layout_hash"] = _sha3_text(fingerprint["page_phash"] or fingerprint["document_hash"])
    return fingerprint


def _hash_distance(left: str, right: str) -> Optional[int]:
    if not left or not right:
        return None
    try:
        return (int(left, 16) ^ int(right, 16)).bit_count()
    except ValueError:
        return None


def _token_jaccard(left: Iterable[str], right: Iterable[str]) -> float:
    left_set = set(left)
    right_set = set(right)
    if not left_set and not right_set:
        return 0.0
    union = left_set | right_set
    return len(left_set & right_set) / len(union) if union else 0.0


def compare_fingerprints(current: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    distance = _hash_distance(str(current.get("page_phash") or ""), str(candidate.get("page_phash") or ""))
    visual_similarity = 0.0 if distance is None else max(0.0, 1.0 - distance / 64.0)
    layout_similarity = 1.0 if current.get("layout_hash") and current.get("layout_hash") == candidate.get("layout_hash") else 0.0

    current_text = current.get("text_fingerprint") or {}
    candidate_text = candidate.get("text_fingerprint") or {}
    if isinstance(candidate_text, str):
        try:
            candidate_text = json.loads(candidate_text)
        except json.JSONDecodeError:
            candidate_text = {}
    text_similarity = _token_jaccard(current_text.get("tokens") or [], candidate_text.get("tokens") or [])
    same_employer = bool(
        current.get("employer_name")
        and candidate.get("employer_name")
        and str(current["employer_name"]).strip().lower() == str(candidate["employer_name"]).strip().lower()
    )
    same_salary = False
    try:
        same_salary = (
            current.get("salary_amount") is not None
            and candidate.get("salary_amount") is not None
            and abs(float(current["salary_amount"]) - float(candidate["salary_amount"])) < 1.0
        )
    except (TypeError, ValueError):
        same_salary = False

    same_seal = bool(current.get("seal_hash") and current.get("seal_hash") == candidate.get("seal_hash"))
    score = (
        visual_similarity * 0.42
        + layout_similarity * 0.17
        + text_similarity * 0.29
        + (0.08 if same_employer else 0.0)
        + (0.04 if same_salary else 0.0)
        + (0.03 if same_seal else 0.0)
    )
    current_employee = str(current.get("employee_name") or "").strip().lower()
    candidate_employee = str(candidate.get("employee_name") or "").strip().lower()
    different_employee = bool(current_employee and candidate_employee and current_employee != candidate_employee)

    return {
        "doc_id": candidate.get("doc_id"),
        "score": round(min(float(score), 1.0), 4),
        "visual_similarity": round(float(visual_similarity), 4),
        "layout_similarity": round(float(layout_similarity), 4),
        "text_similarity": round(float(text_similarity), 4),
        "same_employer": same_employer,
        "same_salary": same_salary,
        "same_seal": same_seal,
        "different_employee": different_employee,
        "candidate_employee": candidate.get("employee_name"),
        "candidate_employer": candidate.get("employer_name"),
        "candidate_salary": candidate.get("salary_amount"),
    }


def find_similarity_matches(
    current: Dict[str, Any],
    candidates: Iterable[Dict[str, Any]],
    threshold: float = SIMILARITY_TRIGGER_SCORE,
) -> List[Dict[str, Any]]:
    matches = []
    for candidate in candidates:
        comparison = compare_fingerprints(current, candidate)
        if comparison["score"] >= threshold and comparison["different_employee"]:
            matches.append(comparison)
    return sorted(matches, key=lambda item: item["score"], reverse=True)[:10]
