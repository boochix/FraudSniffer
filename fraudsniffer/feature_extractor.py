from __future__ import annotations

import logging
import math
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from .models import FeatureStatus, FeatureValue, OCRResult, SealEvidence
from .ocr import (
    PAYSLIP_CORE_FIELDS,
    run_payslip_ocr,
    run_income_tax_ocr,
    run_gst_ocr,
    run_company_reg_ocr,
    run_utility_bill_ocr,
)
from .seal_phash import analyze_seal

logger = logging.getLogger(__name__)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _metadata_creation_delta(metadata: Dict[str, Any]) -> FeatureValue:
    created = _parse_date(metadata.get("pdf_created_date") or metadata.get("created_date"))
    claimed = _parse_date(metadata.get("claimed_document_date") or metadata.get("document_date"))
    if not created or not claimed:
        return FeatureValue(
            value=None,
            status=FeatureStatus.UNAVAILABLE,
            evidence="PDF creation date or claimed document date is unavailable.",
        )
    delta = abs((created - claimed).days)
    return FeatureValue(
        value=float(delta),
        status=FeatureStatus.REAL,
        evidence=f"PDF creation date differs from claimed date by {delta} days.",
    )


def _template_score(text: str) -> FeatureValue:
    if not text:
        return FeatureValue(None, FeatureStatus.UNAVAILABLE, "No text available for template scoring.")
    lines = [line.strip().lower() for line in text.splitlines() if line.strip()]
    if not lines:
        return FeatureValue(None, FeatureStatus.UNAVAILABLE, "No text lines available.")
    repeated = len(lines) - len(set(lines))
    score = min(repeated / max(len(lines), 1) + text.count("{{") * 0.15, 1.0)
    return FeatureValue(
        round(score, 3),
        FeatureStatus.DERIVED,
        f"Template score derived from {repeated} repeated lines across extracted text.",
    )


# Core fields per document type for parse coverage computation
DOCUMENT_CORE_FIELDS = {
    "PAYSLIP": ("employee_name", "employer_name", "salary_amount", "date"),
    "INCOME_TAX_FORM": ("employee_name", "pan_number", "assessment_year"),
    "GST_REGISTRATION": ("company_name", "gstin"),
    "COMPANY_REGISTRATION": ("company_name", "cin"),
    "UTILITY_BILL": ("employee_name", "date"),
}
DOCUMENT_CORE_FIELDS_DEFAULT = ("date",)  # Fallback for unknown types


def _compute_parse_coverage(ocr: OCRResult, document_type: str = "PAYSLIP") -> FeatureValue:
    """Compute parse coverage score = extracted_core_fields / expected_core_fields.
    
    Uses document-type-specific core fields so that a GST certificate isn't
    penalized for missing employee_name or salary_amount.
    """
    core_fields = DOCUMENT_CORE_FIELDS.get(document_type.upper(), DOCUMENT_CORE_FIELDS_DEFAULT)
    extracted = sum(
        1 for name in core_fields
        if ocr.fields.get(name) and ocr.fields[name].status == FeatureStatus.REAL
    )
    total = len(core_fields)
    score = extracted / total if total > 0 else 1.0
    return FeatureValue(
        value=round(score, 3),
        status=FeatureStatus.DERIVED,
        evidence=f"Parse coverage: {extracted}/{total} core fields extracted (type: {document_type}).",
    )


def _form_pdf_mismatch(ocr: OCRResult, metadata: Dict[str, Any]) -> FeatureValue:
    """Task 10: Cross-check OCR-extracted values against form-submitted metadata."""
    mismatches = []
    checks_done = 0

    def _normalize(val: Any) -> str:
        if val is None:
            return ""
        return str(val).strip().lower().replace(",", "").replace("₹", "").replace("rs.", "").replace("rs", "")

    # Check employee name
    meta_name = metadata.get("employee_name")
    ocr_name_field = ocr.fields.get("employee_name")
    if meta_name and ocr_name_field and ocr_name_field.status == FeatureStatus.REAL and ocr_name_field.value:
        checks_done += 1
        if _normalize(meta_name) not in _normalize(ocr_name_field.value) and _normalize(ocr_name_field.value) not in _normalize(meta_name):
            mismatches.append(f"employee_name: form='{meta_name}' vs pdf='{ocr_name_field.value}'")

    # Check employer name
    meta_employer = metadata.get("employer_name")
    ocr_employer_field = ocr.fields.get("employer_name")
    if meta_employer and ocr_employer_field and ocr_employer_field.status == FeatureStatus.REAL and ocr_employer_field.value:
        checks_done += 1
        if _normalize(meta_employer) not in _normalize(ocr_employer_field.value) and _normalize(ocr_employer_field.value) not in _normalize(meta_employer):
            mismatches.append(f"employer_name: form='{meta_employer}' vs pdf='{ocr_employer_field.value}'")

    # Check salary
    meta_salary = metadata.get("salary_amount") or metadata.get("salary")
    ocr_salary_field = ocr.fields.get("salary_amount")
    if meta_salary is not None and ocr_salary_field and ocr_salary_field.status == FeatureStatus.REAL and ocr_salary_field.value is not None:
        checks_done += 1
        try:
            meta_val = float(str(meta_salary).replace(",", "").replace("₹", ""))
            ocr_val = float(ocr_salary_field.value)
            if abs(meta_val - ocr_val) / max(meta_val, 1) > 0.10:  # >10% difference
                mismatches.append(f"salary: form={meta_val} vs pdf={ocr_val}")
        except (ValueError, TypeError):
            pass

    # Check job title vs designation
    meta_title = metadata.get("job_title") or metadata.get("designation")
    ocr_desig_field = ocr.fields.get("designation")
    if meta_title and ocr_desig_field and ocr_desig_field.status == FeatureStatus.REAL and ocr_desig_field.value:
        checks_done += 1
        if _normalize(meta_title) not in _normalize(ocr_desig_field.value) and _normalize(ocr_desig_field.value) not in _normalize(meta_title):
            mismatches.append(f"job_title: form='{meta_title}' vs pdf='{ocr_desig_field.value}'")

    if not checks_done:
        return FeatureValue(
            value=None,
            status=FeatureStatus.UNAVAILABLE,
            evidence="Insufficient data for form-PDF cross-validation.",
        )

    mismatch_score = round(len(mismatches) / checks_done, 3)
    evidence = (
        f"Form-PDF mismatch: {len(mismatches)}/{checks_done} fields differ. "
        + "; ".join(mismatches)
    ) if mismatches else f"Form-PDF validation: {checks_done} fields checked, all consistent."

    return FeatureValue(
        value=mismatch_score,
        status=FeatureStatus.DERIVED,
        evidence=evidence,
    )


def extract_features(
    document_path: Path,
    metadata: Dict[str, Any],
    seal_dir: Path,
    reference_seal_path: Path,
) -> tuple[Dict[str, FeatureValue], OCRResult, SealEvidence]:
    doc_type = str(metadata.get("doc_type") or metadata.get("document_type") or "PAYSLIP").upper()
    if doc_type == "PAYSLIP":
        ocr = run_payslip_ocr(document_path, metadata)
    elif doc_type == "INCOME_TAX_FORM":
        ocr = run_income_tax_ocr(document_path, metadata)
    elif doc_type == "GST_REGISTRATION":
        ocr = run_gst_ocr(document_path, metadata)
    elif doc_type == "COMPANY_REGISTRATION":
        ocr = run_company_reg_ocr(document_path, metadata)
    elif doc_type == "UTILITY_BILL":
        ocr = run_utility_bill_ocr(document_path, metadata)
    else:
        ocr = OCRResult(fields={}, ocr_confidence=None, warnings=[], text=str(metadata.get("text", "")))

    text = ocr.text or str(metadata.get("text") or metadata.get("ocr_text") or "")
    entropy = shannon_entropy(text)
    seal = analyze_seal(document_path, metadata, seal_dir, reference_seal_path)

    features: Dict[str, FeatureValue] = {
        "metadata_creation_delta": _metadata_creation_delta(metadata),
        "text_entropy": FeatureValue(
            value=round(entropy, 3),
            status=FeatureStatus.DERIVED if text else FeatureStatus.UNAVAILABLE,
            evidence="Text entropy computed from extracted document text." if text else "Text unavailable.",
        ),
        "template_score": _template_score(text),
        "seal_phash_distance": FeatureValue(
            value=seal.seal_phash_distance,
            status=seal.feature_status,
            evidence=seal.evidence,
        ),
        "property_registry_match": FeatureValue(
            value=1.0 if metadata.get("property_registry_match") is False else 0.0,
            status=FeatureStatus.SIMULATED,
            evidence="Registry lookup is simulated for the self-contained MVP.",
        ),
        # Task 5: Parse coverage
        "parse_coverage_score": _compute_parse_coverage(ocr, doc_type),
        # Task 10: Form-PDF mismatch
        "form_pdf_mismatch": _form_pdf_mismatch(ocr, metadata),
    }

    for name, field in ocr.fields.items():
        features[name] = FeatureValue(
            value=field.value,
            status=field.status,
            evidence=field.evidence_text,
        )

    return features, ocr, seal
