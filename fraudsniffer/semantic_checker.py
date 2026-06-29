from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Dict, Optional

from .models import FeatureStatus, ReasonCode, SemanticCheckResult, SALARY_BANDS


@dataclass
class _CleanField:
    value: Any


def _is_available(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, dict):
        return value.get("status") not in {FeatureStatus.UNAVAILABLE.value, "UNAVAILABLE"}
    return value not in {"", "UNAVAILABLE"}


def _unwrap(value: Any) -> Any:
    if isinstance(value, dict):
        return value.get("value")
    return value


def _clean_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    return {key: _unwrap(value) for key, value in fields.items() if _is_available(value)}


def _float(value: Any) -> Optional[float]:
    try:
        return float(str(value).replace(",", "").replace("₹", "").strip())
    except (TypeError, ValueError):
        return None


def _parse_date(value: Any) -> Optional[date]:
    if not value:
        return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%m/%d/%Y", "%d %B %Y", "%d %b %Y"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def _job_salary_mismatch_score(job_title: str, salary: float) -> float:
    title = job_title.lower()
    for keyword, (low, high) in sorted(SALARY_BANDS.items(), key=lambda item: len(item[0]), reverse=True):
        if keyword not in title:
            continue
        if low <= salary <= high:
            return 0.0
        if salary > high:
            ratio = salary / max(high, 1.0)
        else:
            ratio = low / max(salary, 1.0)
        return 0.65 if ratio >= 2.0 else 0.40
    return 0.0


def local_semantic_stub(fields: Dict[str, Any]) -> SemanticCheckResult:
    clean = _clean_fields(fields)
    useful_keys = {
        key
        for key in clean
        if key
        in {
            "employer_name",
            "company_name",
            "employee_name",
            "salary_amount",
            "city",
            "job_title",
            "designation",
            "document_date",
            "employment_duration",
            "loan_amount",
            "bank_account",
            "employee_id",
            "department",
            "date_of_issue",
        }
    }
    if len(useful_keys) < 3:
        return SemanticCheckResult(
            score=0.08,
            rationale="Insufficient reliable fields for semantic inconsistency check.",
            reason_code=None,
            source="LOCAL_STUB",
        )

    score = 0.0
    reasons: list[str] = []
    salary = _float(clean.get("salary_amount"))
    loan = _float(clean.get("loan_amount"))

    if salary and loan:
        ratio = loan / max(salary, 1.0)
        if ratio > 80:
            score += 0.20
            reasons.append("loan amount is high relative to monthly salary")
        if ratio > 120:
            score += 0.15
            reasons.append("loan-to-income ratio is extreme")

    job_title = str(clean.get("job_title") or clean.get("designation") or "").lower()
    if salary and job_title:
        mismatch_score = _job_salary_mismatch_score(job_title, salary)
        if mismatch_score:
            score += mismatch_score
            reasons.append("salary does not fit expected job-title band")

    duration = _float(clean.get("employment_duration"))
    if duration is not None and duration < 6 and loan and loan > 2_000_000:
        score += 0.10
        reasons.append("short employment duration for a large loan")

    doc_date = _parse_date(clean.get("document_date"))
    if doc_date:
        age_days = (date.today() - doc_date).days
        if age_days < 0 or age_days > 365:
            score += 0.10
            reasons.append("document date is future-dated or stale")

    employer = str(clean.get("employer_name") or "").strip()
    if employer and (len(employer) < 3 or employer.lower() in {"company", "employer", "na", "n/a"}):
        score += 0.10
        reasons.append("employer name is too generic")

    score = min(score, 1.0)
    if score >= 0.65:
        rationale = "Fields appear internally inconsistent: " + "; ".join(reasons) + "."
        reason_code = ReasonCode.SEMANTIC_INCOHERENCE.value
    elif reasons:
        rationale = "Available fields show mild inconsistency: " + "; ".join(reasons) + "."
        reason_code = None
    else:
        rationale = "Available fields are semantically consistent."
        reason_code = None

    return SemanticCheckResult(
        score=round(score, 3),
        rationale=rationale,
        reason_code=reason_code,
        source="LOCAL_STUB",
    )


def check_semantic_coherence(fields: Dict[str, Any]) -> SemanticCheckResult:
    """Run deterministic local semantic consistency check."""
    return local_semantic_stub(fields)
