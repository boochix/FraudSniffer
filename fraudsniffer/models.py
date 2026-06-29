from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


MODEL_VERSION = "fraud_model_v1.0"


class FeatureStatus(str, Enum):
    REAL = "REAL"
    DERIVED = "DERIVED"
    LLM_INFERRED = "LLM_INFERRED"
    SIMULATED = "SIMULATED"
    UNAVAILABLE = "UNAVAILABLE"


class PipelineState(str, Enum):
    UPLOADED = "UPLOADED"
    HASHED = "HASHED"
    PARSED = "PARSED"
    OCR_COMPLETE = "OCR_COMPLETE"
    FEATURES_EXTRACTED = "FEATURES_EXTRACTED"
    SEMANTIC_CHECKED = "SEMANTIC_CHECKED"
    FORENSICS_EVALUATED = "FORENSICS_EVALUATED"
    SIMILARITY_EVALUATED = "SIMILARITY_EVALUATED"
    RULES_EVALUATED = "RULES_EVALUATED"
    ML_SCORED = "ML_SCORED"
    CASE_CREATED = "CASE_CREATED"
    WEBHOOK_SENT = "WEBHOOK_SENT"
    ERROR = "ERROR"
    FINALIZED = "FINALIZED"


class RiskState(str, Enum):
    LOW = "LOW"
    WATCH = "WATCH"
    SUSPECT = "SUSPECT"
    BLOCK = "BLOCK"


class ReasonCode(str, Enum):
    SEMANTIC_INCOHERENCE = "SEMANTIC_INCOHERENCE"
    SALARY_OUTLIER = "SALARY_OUTLIER"
    META_BACKDATE = "META_BACKDATE"
    HASH_CHAIN_BREAK = "HASH_CHAIN_BREAK"
    TEMPLATE_GENERATED = "TEMPLATE_GENERATED"
    PACKAGE_MISMATCH = "PACKAGE_MISMATCH"
    SEAL_MISMATCH = "SEAL_MISMATCH"
    GHOST_PROPERTY = "GHOST_PROPERTY"
    OCR_INCONSISTENCY = "OCR_INCONSISTENCY"
    PARSE_COVERAGE_LOW = "PARSE_COVERAGE_LOW"
    FORM_PDF_MISMATCH = "FORM_PDF_MISMATCH"
    JOB_SALARY_ANOMALY = "JOB_SALARY_ANOMALY"
    OCR_EXTRACTION_FAILED = "OCR_EXTRACTION_FAILED"
    # Advanced forensics
    ELA_TAMPERING = "ELA_TAMPERING"
    PDF_FONT_MISMATCH = "PDF_FONT_MISMATCH"
    PDF_OBJECT_ANOMALY = "PDF_OBJECT_ANOMALY"
    HIDDEN_TEXT_LAYER = "HIDDEN_TEXT_LAYER"
    RAW_OCR_DIVERGENCE = "RAW_OCR_DIVERGENCE"
    CROSS_DOCUMENT_REUSE = "CROSS_DOCUMENT_REUSE"
    # ── Behavioral Analytics ──
    DEVICE_CLONE = "DEVICE_CLONE"
    IMPOSSIBLE_TRAVEL = "IMPOSSIBLE_TRAVEL"
    VPN_DETECTED = "VPN_DETECTED"
    SCRIPTED_SUBMISSION = "SCRIPTED_SUBMISSION"
    KNOWN_DEVICE_CLUSTER = "KNOWN_DEVICE_CLUSTER"
    REPEATED_PATTERN = "REPEATED_PATTERN"
    # ── External Registry Verification ──
    PAN_NAME_MISMATCH = "PAN_NAME_MISMATCH"
    COMPANY_NOT_FOUND = "COMPANY_NOT_FOUND"
    IFSC_INVALID = "IFSC_INVALID"
    BANK_ACCOUNT_MISMATCH = "BANK_ACCOUNT_MISMATCH"
    # ── New Document Type Reason Codes ──
    GSTIN_FORMAT_INVALID = "GSTIN_FORMAT_INVALID"
    CIN_FORMAT_INVALID = "CIN_FORMAT_INVALID"
    GST_STATE_CODE_INVALID = "GST_STATE_CODE_INVALID"
    GSTIN_PAN_MISMATCH = "GSTIN_PAN_MISMATCH"
    DUPLICATE_DOCUMENT = "DUPLICATE_DOCUMENT"
    SIMILAR_DOCUMENT_FOUND = "SIMILAR_DOCUMENT_FOUND"
    BILL_CONSUMER_MISMATCH = "BILL_CONSUMER_MISMATCH"
    BILL_STALE = "BILL_STALE"
    BILL_MATH_MISMATCH = "BILL_MATH_MISMATCH"
    TAX_MATH_MISMATCH = "TAX_MATH_MISMATCH"


@dataclass
class OCRField:
    value: Optional[Any]
    status: FeatureStatus
    ocr_confidence: Optional[float] = None
    evidence_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "status": self.status.value,
            "ocr_confidence": self.ocr_confidence,
            "evidence_text": self.evidence_text,
        }


@dataclass
class OCRResult:
    fields: Dict[str, OCRField]
    ocr_confidence: Optional[float]
    warnings: List[str] = field(default_factory=list)
    text: str = ""

    def field_value(self, name: str) -> Optional[Any]:
        field_obj = self.fields.get(name)
        if not field_obj or field_obj.status == FeatureStatus.UNAVAILABLE:
            return None
        return field_obj.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fields": {key: value.to_dict() for key, value in self.fields.items()},
            "ocr_confidence": self.ocr_confidence,
            "ocr_warnings": list(self.warnings),
        }


@dataclass
class FeatureValue:
    value: Optional[Any]
    status: FeatureStatus
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "status": self.status.value,
            "evidence": self.evidence,
        }


@dataclass
class SemanticCheckResult:
    score: float
    rationale: str
    reason_code: Optional[str]
    source: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(float(self.score), 3),
            "rationale": self.rationale,
            "reason_code": self.reason_code,
            "source": self.source,
        }


@dataclass
class SealEvidence:
    seal_phash_distance: Optional[float]
    raw_hamming_distance: Optional[int]
    feature_status: FeatureStatus
    evidence: str
    extracted_seal_path: Optional[str] = None
    reference_seal_path: Optional[str] = None

    def to_dict(self, doc_id: str) -> Dict[str, Any]:
        return {
            "seal_phash_distance": self.seal_phash_distance,
            "raw_hamming_distance": self.raw_hamming_distance,
            "feature_status": self.feature_status.value,
            "evidence": self.evidence,
            "extracted_seal_url": (
                f"/api/documents/{doc_id}/seal/extracted" if self.extracted_seal_path else None
            ),
            "reference_seal_url": (
                f"/api/documents/{doc_id}/seal/reference" if self.reference_seal_path else None
            ),
        }


@dataclass
class RiskResult:
    doc_id: str
    fraud_score: float
    p_value: float
    state: RiskState
    ui_state_label: str
    processing_time_ms: Optional[int]
    model_version: str
    final_reason_summary: str
    risk_decision_reason_codes: List[str]
    confidence_breakdown: Dict[str, float]
    semantic_check: SemanticCheckResult
    feature_status: Dict[str, str]
    ocr_confidence: Optional[float]
    ocr_warnings: List[str]
    seal_evidence: SealEvidence
    warnings: List[str] = field(default_factory=list)
    pipeline_state: PipelineState = PipelineState.FINALIZED
    artifacts: Dict[str, Optional[str]] = field(default_factory=dict)
    review: Dict[str, Optional[str]] = field(default_factory=dict)
    webhook_status: Dict[str, Optional[str]] = field(default_factory=dict)
    feature_values: Dict[str, Any] = field(default_factory=dict)
    behavioral_risks: List[Dict[str, Any]] = field(default_factory=list)
    advanced_forensics: Dict[str, Any] = field(default_factory=dict)
    similarity_matches: List[Dict[str, Any]] = field(default_factory=list)
    external_verification: Dict[str, Any] = field(default_factory=dict)
    document_type: str = "UNKNOWN"
    classification_confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "document_type": self.document_type,
            "classification_confidence": round(float(self.classification_confidence), 3) if self.classification_confidence is not None else None,
            "fraud_score": round(float(self.fraud_score), 3),
            "p_value": round(float(self.p_value), 3),
            "state": self.state.value,
            "ui_state_label": self.ui_state_label,
            "processing_time_ms": self.processing_time_ms,
            "model_version": self.model_version,
            "final_reason_summary": self.final_reason_summary,
            "risk_decision_reason_codes": list(self.risk_decision_reason_codes),
            "confidence_breakdown": {
                key: round(float(value), 3) for key, value in self.confidence_breakdown.items()
            },
            "semantic_check": self.semantic_check.to_dict(),
            "feature_status": dict(self.feature_status),
            "ocr_confidence": self.ocr_confidence,
            "ocr_warnings": list(self.ocr_warnings),
            "warnings": list(self.warnings),
            "seal_evidence": self.seal_evidence.to_dict(self.doc_id),
            "pipeline_state": self.pipeline_state.value,
            "artifacts": dict(self.artifacts),
            "review": dict(self.review),
            "webhook_status": dict(self.webhook_status),
            "feature_values": dict(self.feature_values),
            "behavioral_risks": list(self.behavioral_risks),
            "advanced_forensics": dict(self.advanced_forensics),
            "similarity_matches": list(self.similarity_matches),
            "external_verification": dict(self.external_verification),
        }


def ui_label_for_state(state: RiskState, integrity_failure: bool = False) -> str:
    if integrity_failure:
        return "REJECTED - INTEGRITY FAILURE"
    return {
        RiskState.LOW: "LOW RISK",
        RiskState.WATCH: "NEEDS REVIEW",
        RiskState.SUSPECT: "HIGH FRAUD RISK",
        RiskState.BLOCK: "CRITICAL FRAUD RISK",
    }[state]


@dataclass
class TelemetryData:
    """Client-side browser/device telemetry captured during document submission."""
    canvas_fingerprint: str = ""
    ip_address: str = ""
    timezone: str = ""
    language: str = ""
    screen_resolution: str = ""
    platform: str = ""
    user_agent: str = ""
    vpn_detected: bool = False
    proxy_detected: bool = False
    tor_detected: bool = False
    keystroke_duration_ms: int = 0
    submission_duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canvas_fingerprint": self.canvas_fingerprint,
            "ip_address": self.ip_address,
            "timezone": self.timezone,
            "language": self.language,
            "screen_resolution": self.screen_resolution,
            "platform": self.platform,
            "user_agent": self.user_agent,
            "vpn_detected": self.vpn_detected,
            "proxy_detected": self.proxy_detected,
            "tor_detected": self.tor_detected,
            "keystroke_duration_ms": self.keystroke_duration_ms,
            "submission_duration_ms": self.submission_duration_ms,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TelemetryData":
        return cls(
            canvas_fingerprint=str(data.get("canvas_fingerprint", "")),
            ip_address=str(data.get("ip_address", "")),
            timezone=str(data.get("timezone", "")),
            language=str(data.get("language", "")),
            screen_resolution=str(data.get("screen_resolution", "")),
            platform=str(data.get("platform", "")),
            user_agent=str(data.get("user_agent", "")),
            vpn_detected=bool(data.get("vpn_detected", False)),
            proxy_detected=bool(data.get("proxy_detected", False)),
            tor_detected=bool(data.get("tor_detected", False)),
            keystroke_duration_ms=int(data.get("keystroke_duration_ms", 0)),
            submission_duration_ms=int(data.get("submission_duration_ms", 0)),
        )


SALARY_BANDS = {
    "intern": (0, 50_000),
    "junior": (0, 80_000),
    "trainee": (0, 40_000),
    "assistant": (10_000, 80_000),
    "executive": (15_000, 150_000),
    "sales executive": (15_000, 100_000),
    "junior sales executive": (10_000, 60_000),
    "teacher": (15_000, 120_000),
    "software engineer": (25_000, 400_000),
    "senior engineer": (80_000, 600_000),
    "manager": (50_000, 600_000),
    "director": (150_000, 1_500_000),
    "ceo": (200_000, 5_000_000),
}

UTILITY_BILL_MAX_AGE_DAYS = 90
