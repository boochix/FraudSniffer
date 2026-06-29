from __future__ import annotations

import hashlib
import json
import logging
import shutil
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

from .feature_extractor import extract_features
from .models import (
    MODEL_VERSION,
    FeatureStatus,
    FeatureValue,
    PipelineState,
    ReasonCode,
    RiskResult,
    RiskState,
    SemanticCheckResult,
    TelemetryData,
    ui_label_for_state,
    SALARY_BANDS,
    UTILITY_BILL_MAX_AGE_DAYS,
)
from .seal_phash import create_annotated_artifact
from .semantic_checker import check_semantic_coherence
from .storage import FraudStorage
from .webhook import post_webhook
from .ocr import PAYSLIP_CORE_FIELDS, safe_float, auto_detect_document_type
from .pqc_audit import PQCAuditTrail
from .ml_detector import DocumentAnomalyDetector, SalaryOutlierScorer
from .behavioral_detector import BehavioralDetector
from .adversarial_text import analyze_adversarial_text
from .document_similarity import build_document_fingerprint, find_similarity_matches
from .pdf_forensics import analyze_pdf_forensics, detect_pdf_type
from .visual_forensics import analyze_visual_forensics
from .registry_verifier import (
    verify_ifsc_code,
    verify_pan_registry,
    verify_company_existence,
    verify_bank_account_penny_drop,
    verify_gst_registry,
    verify_cin_registry,
)


class FraudSnifferService:
    def __init__(
        self,
        root_dir: Path | str = "data",
        db_path: Path | str | None = None,
        model_version: str = MODEL_VERSION,
        webhook_url: Optional[str] = None,
    ):
        self.root_dir = Path(root_dir).resolve()
        self.original_dir = (self.root_dir / "documents" / "originals").resolve()
        self.annotated_dir = (self.root_dir / "documents" / "annotated").resolve()
        self.seal_dir = (self.root_dir / "documents" / "seals").resolve()
        self.forensics_dir = (self.root_dir / "documents" / "forensics").resolve()
        self.reference_dir = (self.root_dir / "reference").resolve()
        for path in (
            self.original_dir,
            self.annotated_dir,
            self.seal_dir,
            self.forensics_dir,
            self.reference_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)
        self.reference_seal_path = self.reference_dir / "canara_seal.png"
        self.storage = FraudStorage(
            Path(db_path).resolve() if db_path else self.root_dir / "fraudsniffer.db"
        )
        self.audit_trail = PQCAuditTrail(self.root_dir / "pqc_logs")
        self.pqc_startup_diagnostics = self.audit_trail.run_startup_self_test()
        self.behavioral_detector = BehavioralDetector(self.storage)
        self.model_version = model_version
        self.webhook_url = webhook_url

        # ── Phase 3: Graph Intelligence (graceful degradation) ──
        try:
            from .graph_intel import FraudGraphIntel
            self.graph_intel = FraudGraphIntel()
            if self.graph_intel.available:
                logger.info("Neo4j Graph Intelligence initialized successfully")
            else:
                logger.info("Neo4j Graph Intelligence not available — running without graph features")
        except Exception as e:
            logger.info(f"Graph Intelligence disabled: {e}")
            # Create a stub so hasattr checks work
            class _GraphStub:
                available = False
            self.graph_intel = _GraphStub()

    def _process_file_internal(
        self,
        file_path: Path | str,
        metadata: Optional[Dict[str, Any]] = None,
        doc_id: Optional[str] = None,
        telemetry: Optional[TelemetryData] = None,
    ) -> RiskResult:
        start = time.perf_counter()
        metadata = dict(metadata or {})
        source = Path(file_path)
        if not source.exists():
            raise FileNotFoundError(source)
        doc_id = doc_id or metadata.get("doc_id") or f"doc_{uuid.uuid4().hex[:12]}"
        original_path = (self.original_dir / f"{doc_id}{source.suffix or '.bin'}").resolve()
        shutil.copyfile(source, original_path)

        # Verify file was actually persisted
        if not original_path.exists():
            raise FileNotFoundError(
                f"File copy failed: {original_path} does not exist after save"
            )
        logger.info(f"SAVED FILE TO: {original_path}")
        logger.info(f"EXISTS AFTER SAVE: {original_path.exists()}")

        # PQC audit log: start document tracking
        self.audit_trail.record_event(doc_id, "UPLOADED", {"original_path": str(original_path)})

        file_bytes = original_path.read_bytes()
        file_hash = hashlib.sha3_256(file_bytes).hexdigest()
        self.storage.create_document(doc_id, original_path, file_hash, metadata)
        self.storage.record_state(doc_id, PipelineState.UPLOADED)
        
        # PQC audit log: record hashing event
        self.audit_trail.record_event(doc_id, "HASHED", {"file_hash_sha3": file_hash})
        self.storage.record_state(doc_id, PipelineState.HASHED, {"file_hash_sha3": file_hash})

        integrity_failure = bool(
            metadata.get("previous_hash") and metadata.get("previous_hash") != file_hash
        )

        # ── Scan Detection Stage ─────────────────────────────────
        # Classify the document BEFORE OCR to route thresholds.
        # DIGITAL  = native PDF with embedded text layer
        # SCANNED  = image-only PDF from scanner/phone
        # IMAGE    = raw image file (jpg, png, etc.)
        scan_mode = detect_pdf_type(original_path)
        logger.info(f"SCAN MODE DETECTED: {scan_mode} for {original_path.name}")
        metadata["scan_mode"] = scan_mode

        # Extract text for classification
        text = str(metadata.get("ocr_text") or metadata.get("text") or "").strip()
        is_digital = True
        if not text:
            from .ocr import _extract_text_from_file
            text, is_digital = _extract_text_from_file(original_path)
            metadata["text"] = text

        doc_type_meta = metadata.get("doc_type") or metadata.get("document_type")
        if doc_type_meta:
            classification = {"document_type": str(doc_type_meta).upper(), "confidence": 1.0}
        else:
            classification = auto_detect_document_type(text)
            
        metadata["document_type"] = classification["document_type"]
        metadata["doc_type"] = classification["document_type"]

        # PQC audit log: record document classification event
        self.audit_trail.record_event(doc_id, "DOCUMENT_CLASSIFIED", {
            "document_type": classification["document_type"],
            "confidence": classification["confidence"]
        })

        # PQC audit log: record parsing event
        self.audit_trail.record_event(doc_id, "PARSED", {"metadata": metadata})
        self.storage.record_state(doc_id, PipelineState.PARSED, {
            "document_type": classification["document_type"],
            "classification_confidence": classification["confidence"]
        })
        features, ocr, seal = extract_features(
            original_path,
            metadata,
            self.seal_dir,
            self.reference_seal_path,
        )
        # PQC audit log: record OCR complete
        self.audit_trail.record_event(doc_id, "OCR_COMPLETE", {
            "ocr_confidence": ocr.ocr_confidence,
            "ocr_warnings": ocr.warnings,
            "fields_extracted": [k for k, v in ocr.fields.items() if v.status == FeatureStatus.REAL]
        })
        self.storage.record_state(
            doc_id,
            PipelineState.OCR_COMPLETE,
            {"ocr_confidence": ocr.ocr_confidence, "ocr_warnings": ocr.warnings},
        )

        # ── External Registry Verification ──
        company_val = ocr.fields.get("company_name").value if ocr.fields.get("company_name") else None
        if not company_val and ocr.fields.get("employer_name"):
            company_val = ocr.fields.get("employer_name").value
            
        company_res = {"valid": False, "error": "Company name not found in document"}
        if company_val:
            company_res = verify_company_existence(company_val)
            
        pan_val = ocr.fields.get("pan_number").value if ocr.fields.get("pan_number") else None
        employee_val = ocr.fields.get("employee_name").value if ocr.fields.get("employee_name") else None
        
        pan_res = {"valid": False, "error": "PAN or employee name not found in document"}
        if pan_val and employee_val:
            pan_res = verify_pan_registry(pan_val, employee_val)
            
        ifsc_val = ocr.fields.get("ifsc_code").value if ocr.fields.get("ifsc_code") else None
        ifsc_res = {"valid": False, "error": "IFSC code not found in document"}
        if ifsc_val:
            ifsc_res = verify_ifsc_code(ifsc_val)
            
        acct_val = ocr.fields.get("bank_account").value if ocr.fields.get("bank_account") else None
        acct_res = {"valid": False, "error": "Bank account or employee name not found in document"}
        if acct_val and employee_val:
            acct_res = verify_bank_account_penny_drop(acct_val, ifsc_val or "", employee_val)
            
        gst_res = {"valid": False, "error": "GSTIN not found in document"}
        gstin_val = ocr.fields.get("gstin").value if ocr.fields.get("gstin") else None
        if gstin_val and company_val:
            gst_res = verify_gst_registry(gstin_val, company_val)
            
        cin_res = {"valid": False, "error": "CIN not found in document"}
        cin_val = ocr.fields.get("cin").value if ocr.fields.get("cin") else None
        if cin_val and company_val:
            cin_res = verify_cin_registry(cin_val, company_val)
            
        ext_verif_results = {
            "company": company_res,
            "pan": pan_res,
            "ifsc": ifsc_res,
            "bank_account": acct_res,
            "gst": gst_res,
            "cin": cin_res
        }
        
        # Log the EXTERNAL_VERIFIED event to the PQC cryptographic audit ledger
        self.audit_trail.record_event(doc_id, "EXTERNAL_VERIFIED", {
            "ifsc_verified": bool(ifsc_res.get("valid")),
            "pan_verified": bool(pan_res.get("valid")),
            "company_verified": bool(company_res.get("valid")),
            "bank_account_verified": bool(acct_res.get("valid")),
            "gst_verified": bool(gst_res.get("valid")),
            "cin_verified": bool(cin_res.get("valid")),
            "verification_details": ext_verif_results
        })
        
        # PQC audit log: record feature extraction complete
        self.audit_trail.record_event(doc_id, "FEATURES_EXTRACTED", {"features": list(features.keys())})
        self.storage.record_state(doc_id, PipelineState.FEATURES_EXTRACTED)

        designation_field = ocr.fields.get("designation")
        designation_payload = (
            designation_field.to_dict()
            if designation_field and designation_field.status == FeatureStatus.REAL
            else None
        )
        semantic_fields: Dict[str, Any] = {
            "employer_name": ocr.fields.get("employer_name", {}).to_dict()
            if "employer_name" in ocr.fields
            else None,
            "company_name": ocr.fields.get("company_name", {}).to_dict()
            if "company_name" in ocr.fields
            else None,
            "employee_name": ocr.fields.get("employee_name", {}).to_dict()
            if "employee_name" in ocr.fields
            else None,
            "salary_amount": ocr.fields.get("salary_amount", {}).to_dict()
            if "salary_amount" in ocr.fields
            else None,
            "document_date": ocr.fields.get("date", {}).to_dict() if "date" in ocr.fields else None,
            "designation": designation_payload,
            "city": metadata.get("city"),
            "job_title": metadata.get("job_title") or designation_payload,
            "employment_duration": metadata.get("employment_duration"),
            "loan_amount": metadata.get("loan_amount"),
            "bank_account": ocr.fields.get("bank_account", {}).to_dict()
            if "bank_account" in ocr.fields
            else None,
            "employee_id": ocr.fields.get("employee_id", {}).to_dict()
            if "employee_id" in ocr.fields
            else None,
            "department": ocr.fields.get("department", {}).to_dict()
            if "department" in ocr.fields
            else None,
            "date_of_issue": ocr.fields.get("date_of_issue", {}).to_dict()
            if "date_of_issue" in ocr.fields
            else None,
        }
        semantic = check_semantic_coherence(semantic_fields)
        # PQC audit log: record semantic check complete
        self.audit_trail.record_event(doc_id, "SEMANTIC_CHECKED", {"source": semantic.source, "score": semantic.score})
        self.storage.record_state(
            doc_id,
            PipelineState.SEMANTIC_CHECKED,
            {"source": semantic.source, "score": semantic.score},
        )

        confidence: Dict[str, float] = {}
        reasons: list[str] = []

        if integrity_failure:
            confidence["hash_chain_integrity"] = 1.0
            reasons.append(ReasonCode.HASH_CHAIN_BREAK.value)

        meta = features.get("metadata_creation_delta")
        if meta and meta.status == FeatureStatus.REAL and meta.value is not None and meta.value > 30:
            confidence["metadata_backdating"] = 0.21
            reasons.append(ReasonCode.META_BACKDATE.value)

        template = features.get("template_score")
        if template and template.status == FeatureStatus.DERIVED and template.value is not None:
            if template.value >= 0.30:
                confidence["template_generation"] = min(0.16, 0.10 + template.value * 0.15)
                reasons.append(ReasonCode.TEMPLATE_GENERATED.value)

        # Base salary checks
        salary_feature = features.get("salary_amount")
        salary = salary_feature.value if salary_feature and salary_feature.status == FeatureStatus.REAL else None
        loan_amount = safe_float(metadata.get("loan_amount"))
        if (
            salary_feature
            and salary_feature.status == FeatureStatus.REAL
            and salary
            and loan_amount
            and loan_amount / max(salary, 1.0) > 80
        ):
            confidence["income_mismatch"] = 0.24
            reasons.append(ReasonCode.SALARY_OUTLIER.value)

        # ML anomaly check 1: Company Salary Z-Score Baselines
        hist_salaries = self.storage.get_historical_salaries()
        employer_feature = ocr.fields.get("employer_name")
        employer_val = employer_feature.value if employer_feature and employer_feature.status == FeatureStatus.REAL else None
        employee_feature = ocr.fields.get("employee_name")
        employee_val = employee_feature.value if employee_feature and employee_feature.status == FeatureStatus.REAL else None
        
        salary_risk = 0.0
        salary_deviation_msg = None
        if salary and employer_val:
            salary_risk, salary_deviation_msg = SalaryOutlierScorer.check_salary(employer_val, salary, hist_salaries)
            if salary_risk > 0.0:
                confidence["salary_outlier_z_score"] = salary_risk
                if ReasonCode.SALARY_OUTLIER.value not in reasons:
                    reasons.append(ReasonCode.SALARY_OUTLIER.value)

        # ML anomaly check 2: Document Structural Text Anomalies
        hist_features = self.storage.get_historical_structural_features()
        current_structural_features = DocumentAnomalyDetector.extract_structural_features(ocr.text)
        ml_score, ml_deviations = DocumentAnomalyDetector.compute_anomaly_score(current_structural_features, hist_features)
        
        if ml_score > 0.0:
            confidence["ml_structural_anomaly"] = ml_score * 0.25
            if ml_score >= 0.50:
                if ReasonCode.OCR_INCONSISTENCY.value not in reasons:
                    reasons.append(ReasonCode.OCR_INCONSISTENCY.value)

        # Arithmetic check warning
        if getattr(ocr, "arithmetic_valid", None) is False:
            confidence["ocr_arithmetic_mismatch"] = 0.30
            if ReasonCode.OCR_INCONSISTENCY.value not in reasons:
                reasons.append(ReasonCode.OCR_INCONSISTENCY.value)

        # Seal mismatch — only penalize when BOTH seal sources are genuine.
        # Skip when: heuristic extraction, synthetic reference, or derived status.
        seal_feature = features.get("seal_phash_distance")
        if (
            seal_feature
            and seal_feature.status == FeatureStatus.REAL  # Not DERIVED (heuristic/synthetic)
            and seal.raw_hamming_distance is not None
            and seal.raw_hamming_distance > 10
            and "heuristic" not in seal.evidence.lower()
            and "synthetic" not in seal.evidence.lower()
        ):
            confidence["seal_mismatch"] = min(0.22, max(0.10, seal_feature.value or 0.0))
            reasons.append(ReasonCode.SEAL_MISMATCH.value)

        # Semantic coherence — skip for scanned docs with no text
        if semantic.reason_code == ReasonCode.SEMANTIC_INCOHERENCE.value:
            if scan_mode == "DIGITAL" or len(text.strip()) > 100:
                confidence["llm_semantic_coherence"] = min(0.22, semantic.score * 0.30)
                reasons.append(ReasonCode.SEMANTIC_INCOHERENCE.value)

        # Parse coverage risk rule — scan-mode-aware.
        # For scanned/image docs with no text, this is NOT fraud — it's inability to read.
        parse_cov = features.get("parse_coverage_score")
        parse_cov_val = parse_cov.value if parse_cov else None
        is_scanned_doc = scan_mode in ("SCANNED", "IMAGE")
        ocr_total_failure = not text.strip() or len(text.strip()) < 30

        _deferred_scan_warning = None  # May be set below for scanned doc OCR failure
        if parse_cov_val is not None and parse_cov_val < 0.50:
            if ocr_total_failure and is_scanned_doc:
                # Scanned doc with no text → NOT fraud, just unreadable.
                # Add informational warning but NO fraud penalty.
                # (warning appended later when all_warnings is initialized)
                _deferred_scan_warning = "MANUAL_REVIEW_UNREADABLE — Scanned document, OCR could not extract text"
            elif ocr_total_failure:
                # Digital PDF but OCR still failed — mild penalty only
                confidence["parse_coverage_low"] = 0.15
                reasons.append(ReasonCode.PARSE_COVERAGE_LOW.value)
            else:
                # Partial extraction — use reduced penalties
                confidence["parse_coverage_low"] = 0.15 if parse_cov_val < 0.25 else 0.10
                reasons.append(ReasonCode.PARSE_COVERAGE_LOW.value)

        # Task 9: Job title ↔ salary anomaly rule
        designation_field = ocr.fields.get("designation")
        sal_feat = features.get("salary_amount")
        net_feat = features.get("net_pay")
        salary_val = (
            sal_feat.value if sal_feat and sal_feat.value is not None
            else (net_feat.value if net_feat and net_feat.value is not None else None)
        )
        ocr_designation = designation_field.value if designation_field and designation_field.status == FeatureStatus.REAL else None
        job_title_str = str(ocr_designation or metadata.get("job_title") or "").lower()
        if salary_val and job_title_str:
            for title, (low, high) in SALARY_BANDS.items():
                if title in job_title_str and not (low <= salary_val <= high):
                    confidence["job_salary_anomaly"] = 0.25
                    reasons.append(ReasonCode.JOB_SALARY_ANOMALY.value)
                    break

        # Task 10: Form-PDF mismatch rule
        mismatch_feature = features.get("form_pdf_mismatch")
        if mismatch_feature and mismatch_feature.status == FeatureStatus.DERIVED and mismatch_feature.value and mismatch_feature.value > 0:
            confidence["form_pdf_mismatch"] = min(0.30, mismatch_feature.value * 0.30)
            reasons.append(ReasonCode.FORM_PDF_MISMATCH.value)

        # ── External Registry Verification Rules ──
        doc_type_val = classification["document_type"]
        if doc_type_val == "PAYSLIP":
            if company_val and not ext_verif_results["company"].get("valid"):
                confidence["company_not_found"] = 0.20
                reasons.append(ReasonCode.COMPANY_NOT_FOUND.value)
                
            if pan_val and employee_val and not ext_verif_results["pan"].get("valid"):
                confidence["pan_name_mismatch"] = 0.35
                reasons.append(ReasonCode.PAN_NAME_MISMATCH.value)
                
            if ifsc_val and not ext_verif_results["ifsc"].get("valid"):
                confidence["ifsc_invalid"] = 0.30
                reasons.append(ReasonCode.IFSC_INVALID.value)
                
            if acct_val and employee_val and not ext_verif_results["bank_account"].get("valid"):
                confidence["bank_account_mismatch"] = 0.35
                reasons.append(ReasonCode.BANK_ACCOUNT_MISMATCH.value)
        elif doc_type_val == "INCOME_TAX_FORM":
            if pan_val and employee_val and not ext_verif_results["pan"].get("valid"):
                confidence["pan_name_mismatch"] = 0.35
                reasons.append(ReasonCode.PAN_NAME_MISMATCH.value)
            if company_val and not ext_verif_results["company"].get("valid"):
                confidence["company_not_found"] = 0.20
                reasons.append(ReasonCode.COMPANY_NOT_FOUND.value)
            if getattr(ocr, "arithmetic_valid", None) is False:
                confidence["tax_math_mismatch"] = 0.30
                reasons.append(ReasonCode.TAX_MATH_MISMATCH.value)
        elif doc_type_val == "GST_REGISTRATION":
            if gstin_val and not ext_verif_results["gst"].get("valid"):
                reason_code = ext_verif_results["gst"].get("reason_code")
                if reason_code == "GSTIN_FORMAT_INVALID":
                    confidence["gstin_format_invalid"] = 0.35
                    reasons.append(ReasonCode.GSTIN_FORMAT_INVALID.value)
                elif reason_code == "GST_STATE_CODE_INVALID":
                    confidence["gst_state_code_invalid"] = 0.30
                    reasons.append(ReasonCode.GST_STATE_CODE_INVALID.value)
                else:
                    confidence["company_not_found"] = 0.20
                    reasons.append(ReasonCode.COMPANY_NOT_FOUND.value)
            elif gstin_val:
                embedded_pan = ext_verif_results["gst"].get("pan")
                meta_pan = metadata.get("pan_number") or metadata.get("pan")
                other_pan = ocr.fields.get("pan_number").value if ocr.fields.get("pan_number") else None
                target_pan = meta_pan or other_pan
                if target_pan and embedded_pan and embedded_pan.strip().upper() != target_pan.strip().upper():
                    confidence["gstin_pan_mismatch"] = 0.30
                    reasons.append(ReasonCode.GSTIN_PAN_MISMATCH.value)
        elif doc_type_val == "COMPANY_REGISTRATION":
            if cin_val and not ext_verif_results["cin"].get("valid"):
                reason_code = ext_verif_results["cin"].get("reason_code")
                if reason_code == "CIN_FORMAT_INVALID":
                    confidence["cin_format_invalid"] = 0.35
                    reasons.append(ReasonCode.CIN_FORMAT_INVALID.value)
                else:
                    confidence["company_not_found"] = 0.20
                    reasons.append(ReasonCode.COMPANY_NOT_FOUND.value)
        elif doc_type_val == "UTILITY_BILL":
            bill_date_str = ocr.fields.get("date").value if ocr.fields.get("date") else None
            if bill_date_str:
                from datetime import datetime, date
                bill_date = None
                for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
                    try:
                        bill_date = datetime.strptime(str(bill_date_str), fmt).date()
                        break
                    except ValueError:
                        continue
                if bill_date:
                    age_days = (date.today() - bill_date).days
                    if age_days > UTILITY_BILL_MAX_AGE_DAYS:
                        confidence["bill_stale"] = 0.25
                        reasons.append(ReasonCode.BILL_STALE.value)
            cust_name = ocr.fields.get("employee_name").value if ocr.fields.get("employee_name") else None
            meta_applicant = metadata.get("employee_name") or metadata.get("customer_name") or metadata.get("applicant_name")
            if cust_name and meta_applicant:
                import difflib
                ratio = difflib.SequenceMatcher(None, str(cust_name).lower(), str(meta_applicant).lower()).ratio()
                if ratio < 0.75:
                    confidence["bill_consumer_mismatch"] = 0.30
                    reasons.append(ReasonCode.BILL_CONSUMER_MISMATCH.value)
            if getattr(ocr, "arithmetic_valid", None) is False:
                confidence["bill_math_mismatch"] = 0.25
                reasons.append(ReasonCode.BILL_MATH_MISMATCH.value)

        # Advanced forensics: ELA, PDF objects/fonts, adversarial text.
        # Pass is_scanned flag so ELA uses a relaxed threshold for scan artifacts.
        visual_forensics = analyze_visual_forensics(
            original_path,
            self.forensics_dir,
            doc_id,
            max_pages=3,
            is_scanned=is_scanned_doc,
        )
        for page in visual_forensics.get("ela", {}).get("pages", []):
            page["artifact_url"] = (
                f"/api/documents/{doc_id}/forensics/ela/{page.get('page', 1)}"
            )

        pdf_forensics_raw = analyze_pdf_forensics(original_path, max_pages=3)
        adversarial_forensics = analyze_adversarial_text(
            original_path,
            ocr.text,
            pdf_forensics_raw,
        )
        pdf_forensics = dict(pdf_forensics_raw)
        raw_text = str(pdf_forensics.pop("raw_text", "") or "")
        visible_text = str(pdf_forensics.pop("visible_text", "") or "")
        pdf_forensics["raw_text_preview"] = raw_text[:500]
        pdf_forensics["visible_text_preview"] = visible_text[:500]

        ela = visual_forensics.get("ela", {})
        if ela.get("triggered"):
            confidence["ela_tampering"] = min(0.30, max(0.12, float(ela.get("max_score") or 0.0)))
            reasons.append(ReasonCode.ELA_TAMPERING.value)

        # Font checks — skip for scanned docs (they have no native font layer)
        font_audit = pdf_forensics.get("font_audit") or {}
        if font_audit.get("triggered") and not is_scanned_doc:
            confidence["pdf_font_mismatch"] = min(0.25, max(0.12, float(font_audit.get("score") or 0.0)))
            reasons.append(ReasonCode.PDF_FONT_MISMATCH.value)

        object_audit = pdf_forensics.get("object_audit") or {}
        if object_audit.get("triggered"):
            confidence["pdf_object_anomaly"] = min(0.25, max(0.12, float(object_audit.get("score") or 0.0)))
            reasons.append(ReasonCode.PDF_OBJECT_ANOMALY.value)

        # Text-layer checks — skip for scanned docs (no embedded text to compare)
        hidden_text = adversarial_forensics.get("hidden_text") or {}
        if hidden_text.get("triggered") and not is_scanned_doc:
            confidence["hidden_text_layer"] = min(0.35, max(0.20, float(hidden_text.get("score") or 0.0)))
            reasons.append(ReasonCode.HIDDEN_TEXT_LAYER.value)

        raw_divergence = adversarial_forensics.get("raw_ocr_divergence") or {}
        if raw_divergence.get("triggered") and not is_scanned_doc:
            confidence["raw_ocr_divergence"] = min(0.35, max(0.12, float(raw_divergence.get("score") or 0.0)))
            reasons.append(ReasonCode.RAW_OCR_DIVERGENCE.value)

        advanced_forensics: Dict[str, Any] = {
            "visual": visual_forensics,
            "pdf": pdf_forensics,
            "adversarial_text": adversarial_forensics,
        }
        self.audit_trail.record_event(doc_id, "FORENSICS_EVALUATED", {
            "ela_score": ela.get("max_score"),
            "pdf_font_anomalies": len(font_audit.get("anomalies") or []),
            "pdf_object_anomalies": len(object_audit.get("anomalies") or []),
            "hidden_text_spans": hidden_text.get("hidden_span_count", 0),
            "raw_ocr_divergence": raw_divergence.get("distance"),
        })
        self.storage.record_state(doc_id, PipelineState.FORENSICS_EVALUATED)

        # Cross-document similarity detection.
        current_fingerprint = build_document_fingerprint(
            document_path=original_path,
            file_hash=file_hash,
            ocr_text=ocr.text,
            employee_name=str(employee_val) if employee_val is not None else None,
            employer_name=str(employer_val) if employer_val is not None else None,
            salary_amount=float(salary) if salary is not None else None,
            seal_path=seal.extracted_seal_path,
        )
        historical_fingerprints = self.storage.list_document_fingerprints(exclude_doc_id=doc_id)
        similarity_matches = find_similarity_matches(current_fingerprint, historical_fingerprints)
        self.storage.save_document_fingerprint(doc_id, current_fingerprint)

        # Check for duplicates or similar documents in historical database
        is_duplicate = False
        top_similar_score = 0.0
        for candidate in historical_fingerprints:
            if candidate.get("document_hash") == file_hash:
                is_duplicate = True
            from .document_similarity import compare_fingerprints
            comparison = compare_fingerprints(current_fingerprint, candidate)
            if comparison["score"] >= 0.99:
                is_duplicate = True
            elif comparison["score"] >= 0.85:
                top_similar_score = max(top_similar_score, comparison["score"])

        if is_duplicate:
            confidence["duplicate_document"] = 0.35
            if ReasonCode.DUPLICATE_DOCUMENT.value not in reasons:
                reasons.append(ReasonCode.DUPLICATE_DOCUMENT.value)
        elif top_similar_score >= 0.85:
            confidence["similar_document_found"] = min(0.35, max(0.20, top_similar_score * 0.35))
            if ReasonCode.SIMILAR_DOCUMENT_FOUND.value not in reasons:
                reasons.append(ReasonCode.SIMILAR_DOCUMENT_FOUND.value)

        if similarity_matches:
            top_score = float(similarity_matches[0].get("score") or 0.0)
            confidence["cross_document_reuse"] = min(0.35, max(0.20, top_score * 0.35))
            if ReasonCode.CROSS_DOCUMENT_REUSE.value not in reasons:
                reasons.append(ReasonCode.CROSS_DOCUMENT_REUSE.value)

        self.audit_trail.record_event(doc_id, "SIMILARITY_EVALUATED", {
            "candidate_count": len(historical_fingerprints),
            "match_count": len(similarity_matches),
            "top_score": similarity_matches[0].get("score") if similarity_matches else None,
        })
        self.storage.record_state(doc_id, PipelineState.SIMILARITY_EVALUATED)

        # Task 7: Collect all warnings
        all_warnings = list(ocr.warnings)
        if parse_cov_val is not None and parse_cov_val < 0.25:
            all_warnings.append("VERY LOW PARSE COVERAGE — Document may be obfuscated or corrupted")
        if _deferred_scan_warning:
            all_warnings.append(_deferred_scan_warning)

        # PQC audit log: record rules evaluation
        self.audit_trail.record_event(doc_id, "RULES_EVALUATED", {"reasons": reasons, "confidence": confidence})
        self.storage.record_state(doc_id, PipelineState.RULES_EVALUATED)

        # ── Behavioral Analytics ──────────────────────────────────
        behavioral_risks: list[Dict[str, Any]] = []
        if telemetry is None:
            telemetry = TelemetryData()  # Empty stub if no telemetry was sent

        # Persist telemetry data
        self.storage.save_telemetry(doc_id, telemetry)

        # Run behavioral checks
        behavioral_result = self.behavioral_detector.evaluate(
            doc_id=doc_id,
            telemetry=telemetry,
            employer_name=employer_val,
            salary_amount=salary,
            seal_phash=None,  # Could pass seal hash here for cross-doc comparison
        )

        for alert in behavioral_result.alerts:
            behavioral_risks.append(alert.to_dict())
            confidence[f"behavioral_{alert.rule.lower()}"] = alert.score
            if alert.rule not in reasons:
                reasons.append(alert.rule)

        # PQC audit log: record behavioral evaluation even when no alerts fire.
        self.audit_trail.record_event(doc_id, "BEHAVIOR_EVALUATED", {
            "fingerprint": telemetry.canvas_fingerprint,
            "ip_address": telemetry.ip_address,
            "risk_triggered": [a.rule for a in behavioral_result.alerts],
            "behavioral_score": behavioral_result.total_score,
        })

        # ── Diminishing Returns Scoring Model ──────────────────────
        # Signals are sorted strongest-first. Each successive signal
        # contributes with declining weight, preventing weak-signal
        # cascade while still rewarding genuine multi-signal fraud.
        #
        #   Signal 1 = 100%   Signal 4 = 30%   Signal 7 = 10%
        #   Signal 2 =  70%   Signal 5 = 20%   Signal 8 =  8%
        #   Signal 3 =  50%   Signal 6 = 15%   Signal 9+ = 5%
        DIMINISHING_WEIGHTS = [1.0, 0.70, 0.50, 0.30, 0.20, 0.15, 0.10, 0.08, 0.05]

        sorted_signals = sorted(confidence.values(), reverse=True)
        weighted_sum = 0.0
        for i, signal_value in enumerate(sorted_signals):
            weight = DIMINISHING_WEIGHTS[i] if i < len(DIMINISHING_WEIGHTS) else 0.05
            weighted_sum += signal_value * weight

        fraud_score = min(weighted_sum, 1.0)
        p_value = max((1.0 - fraud_score) ** 2, 0.001)
        state = _state_for_score(fraud_score, integrity_failure)

        # For scanned docs with OCR failure, cap at WATCH (no SUSPECT/BLOCK from automated signals)
        if is_scanned_doc and ocr_total_failure and state in (RiskState.SUSPECT, RiskState.BLOCK) and not integrity_failure:
            state = RiskState.WATCH
            fraud_score = min(fraud_score, 0.34)  # Keep below WATCH→SUSPECT threshold

        # Parse coverage state override (only for digital docs with partial extraction)
        if parse_cov_val is not None and state == RiskState.LOW and not is_scanned_doc:
            if parse_cov_val < 0.25:
                state = RiskState.WATCH  # Downgraded from SUSPECT — low coverage ≠ fraud
            elif parse_cov_val < 0.50:
                state = RiskState.WATCH
                
        # PQC audit log: record ML scored
        self.audit_trail.record_event(doc_id, "ML_SCORED", {
            "fraud_score": fraud_score,
            "p_value": p_value,
            "state": state.value
        })
        self.storage.record_state(doc_id, PipelineState.ML_SCORED, {"fraud_score": fraud_score})
        self.storage.record_state(doc_id, PipelineState.CASE_CREATED)

        processing_time_ms = int((time.perf_counter() - start) * 1000)
        feature_status = {name: feature.status.value for name, feature in features.items()}
        if semantic.source == "GEMINI":
            feature_status["llm_semantic_coherence"] = FeatureStatus.LLM_INFERRED.value
        else:
            feature_status["llm_semantic_coherence"] = FeatureStatus.DERIVED.value

        # Build feature values dictionary to store actual extracted OCR and ML metrics.
        feature_values = {
            name: (field.value if field.status != FeatureStatus.UNAVAILABLE else None)
            for name, field in ocr.fields.items()
        }
        feature_values.update({
            "employer_name": employer_val,
            "employee_name": employee_val,
            "salary_amount": salary,
            "document_date": ocr.fields.get("date").value
            if ocr.fields.get("date") and ocr.fields["date"].status == FeatureStatus.REAL
            else None,
            "structural_features": current_structural_features,
            "arithmetic_valid": getattr(ocr, "arithmetic_valid", None),
            "arithmetic_log": getattr(ocr, "arithmetic_log", ""),
            "ml_structural_anomaly_score": ml_score,
            "ml_deviations": ml_deviations,
            "salary_deviation_msg": salary_deviation_msg,
        })

        summary = _summary(reasons, state, integrity_failure, ocr.warnings)
        annotated_path = (self.annotated_dir / f"{doc_id}_annotated.png").resolve()
        create_annotated_artifact(original_path, annotated_path, metadata, reasons or [summary])
        logger.info(f"ANNOTATED SAVED TO: {annotated_path}")
        logger.info(f"ANNOTATED EXISTS: {annotated_path.exists()}")

        review = self.storage.get_review(doc_id)
        risk = RiskResult(
            doc_id=doc_id,
            document_type=classification["document_type"],
            classification_confidence=classification["confidence"],
            fraud_score=fraud_score,
            p_value=p_value,
            state=state,
            ui_state_label=ui_label_for_state(state, integrity_failure),
            processing_time_ms=processing_time_ms,
            model_version=self.model_version,
            final_reason_summary=summary,
            risk_decision_reason_codes=list(dict.fromkeys(reasons)),
            confidence_breakdown=confidence,
            semantic_check=semantic,
            feature_status=feature_status,
            ocr_confidence=ocr.ocr_confidence,
            ocr_warnings=ocr.warnings,
            warnings=all_warnings,
            seal_evidence=seal,
            artifacts={
                "original_file_url": f"/api/documents/{doc_id}/original",
                "annotated_file_url": f"/api/documents/{doc_id}/annotated",
                "seal_comparison_url": f"/api/documents/{doc_id}/seal/comparison",
                "forensics_url": f"/api/documents/{doc_id}/forensics",
                "ela_heatmap_urls": [
                    page.get("artifact_url")
                    for page in visual_forensics.get("ela", {}).get("pages", [])
                    if page.get("artifact_url")
                ],
            },
            review=review,
            feature_values=feature_values,
            behavioral_risks=behavioral_risks,
            advanced_forensics=advanced_forensics,
            similarity_matches=similarity_matches,
            external_verification=ext_verif_results,
        )
        if state in {RiskState.SUSPECT, RiskState.BLOCK}:
            webhook_status = post_webhook(self.webhook_url, risk.to_dict())
            risk.webhook_status = webhook_status
            if webhook_status.get("status") == "SENT":
                self.storage.record_state(doc_id, PipelineState.WEBHOOK_SENT, webhook_status)
        else:
            risk.webhook_status = {"status": "SKIPPED", "message": "Webhook only fires on SUSPECT or BLOCK"}
        
        # PQC audit log: record finalized state
        self.audit_trail.record_event(doc_id, "FINALIZED", {
            "state": state.value,
            "final_reason_summary": summary,
            "signature_chain_valid": True
        })
        self.storage.record_state(doc_id, PipelineState.FINALIZED)
        self.storage.save_risk(risk, annotated_path)

        # ── Phase 3: Ingest into fraud intelligence graph ──
        try:
            if hasattr(self, 'graph_intel') and self.graph_intel.available:
                telemetry_dict = telemetry.to_dict() if telemetry else {}
                self.graph_intel.ingest_case(
                    doc_id=doc_id,
                    risk_data=risk.to_dict(),
                    telemetry_data=telemetry_dict,
                    metadata=metadata or {},
                )
                logger.info(f"Graph ingestion complete for {doc_id}")
        except Exception as e:
            logger.warning(f"Graph ingestion failed for {doc_id} (non-fatal): {e}")

        return risk

    def process_file(
        self,
        file_path: Path | str,
        metadata: Optional[Dict[str, Any]] = None,
        doc_id: Optional[str] = None,
        telemetry: Optional[TelemetryData] = None,
    ) -> RiskResult:
        doc_id = doc_id or (metadata or {}).get("doc_id") or f"doc_{uuid.uuid4().hex[:12]}"
        try:
            return self._process_file_internal(file_path, metadata, doc_id, telemetry)
        except Exception as exc:
            logger.exception("Error during document processing pipeline")
            self.audit_trail.record_event(
                doc_id,
                "PROCESSING_ERROR",
                {"error": str(exc), "traceback": traceback.format_exc()},
            )
            try:
                self.storage.record_state(doc_id, PipelineState.ERROR, error_message=str(exc))
            except Exception:
                pass
            raise

    def get_risk(self, doc_id: str) -> Optional[Dict[str, Any]]:
        risk = self.storage.get_risk(doc_id)
        if risk:
            risk["review"] = self.storage.get_review(doc_id)
            risk["processing_timeline"] = self.storage.get_timeline(doc_id)
            # Add PQC audit trail details for presentation in UI
            timeline = self.audit_trail.get_timeline_for_document(doc_id)
            risk["pqc_audit_trail"] = timeline
            
            # Verify the audit trail integrity dynamically on load
            verification = self.audit_trail.verify_chain_integrity()
            risk["pqc_integrity_ok"] = bool(verification.get("ok"))
            risk["pqc_integrity_message"] = verification.get("message")
            risk["verification_result"] = verification
            risk["verification_stats"] = {
                "blocks_verified": verification.get("blocks_verified"),
                "total_blocks": verification.get("total_blocks"),
                "signatures_valid": verification.get("signatures_valid"),
                "total_signatures": verification.get("total_signatures"),
                "verification_percentage": verification.get("verification_percentage"),
                "verification_time_ms": verification.get("verification_time_ms"),
                "verification_failed_at": verification.get("verification_failed_at"),
                "signature_scheme": verification.get("signature_scheme"),
                "chain_version": verification.get("chain_version"),
                "signer_id": verification.get("signer_id"),
            }
        return risk

    def save_review(
        self,
        doc_id: str,
        review_notes: Optional[str],
        reviewed_by: Optional[str],
        manual_verdict: Optional[str],
    ) -> Dict[str, Optional[str]]:
        # PQC audit log: record underwriter review action with Dilithium signature
        self.audit_trail.record_event(doc_id, "REVIEW_SUBMITTED", {
            "reviewed_by": reviewed_by,
            "manual_verdict": manual_verdict,
            "review_notes": review_notes,
        })
        return self.storage.save_review(doc_id, review_notes, reviewed_by, manual_verdict)

    def test_webhook(self, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return post_webhook(self.webhook_url, payload or {"event": "fraudsniffer_webhook_test"})

    def get_paths(self, doc_id: str) -> Optional[Dict[str, Optional[str]]]:
        paths = self.storage.get_document_paths(doc_id)
        risk = self.storage.get_risk(doc_id)
        if paths and risk:
            seal_evidence = risk.get("seal_evidence") or {}
            paths["extracted_seal_path"] = _path_from_url_hint(
                self.seal_dir, doc_id, seal_evidence.get("extracted_seal_url")
            )
            paths["reference_seal_path"] = str(self.reference_seal_path)
        return paths





def _state_for_score(score: float, integrity_failure: bool) -> RiskState:
    if integrity_failure:
        return RiskState.BLOCK
    if score >= 0.85:
        return RiskState.BLOCK
    if score >= 0.60:
        return RiskState.SUSPECT
    if score >= 0.35:
        return RiskState.WATCH
    return RiskState.LOW


def _summary(
    reasons: list[str],
    state: RiskState,
    integrity_failure: bool,
    ocr_warnings: list[str],
) -> str:
    if integrity_failure:
        return "Document rejected because its SHA3-256 hash does not match the prior audit receipt."
    if reasons:
        labels = {
            ReasonCode.META_BACKDATE.value: "metadata timestamp mismatch",
            ReasonCode.SALARY_OUTLIER.value: "abnormal salary-to-loan deviation",
            ReasonCode.SEAL_MISMATCH.value: "seal perceptual-hash mismatch",
            ReasonCode.SEMANTIC_INCOHERENCE.value: "semantic inconsistency",
            ReasonCode.TEMPLATE_GENERATED.value: "template-like repeated formatting",
            ReasonCode.PARSE_COVERAGE_LOW.value: "low parse coverage on core fields",
            ReasonCode.JOB_SALARY_ANOMALY.value: "job title salary band anomaly",
            ReasonCode.FORM_PDF_MISMATCH.value: "form metadata differs from PDF content",
            ReasonCode.OCR_EXTRACTION_FAILED.value: "OCR extraction failure",
            ReasonCode.ELA_TAMPERING.value: "pixel-level ELA tampering evidence",
            ReasonCode.PDF_FONT_MISMATCH.value: "PDF font mismatch",
            ReasonCode.PDF_OBJECT_ANOMALY.value: "PDF object structure anomaly",
            ReasonCode.HIDDEN_TEXT_LAYER.value: "hidden text layer",
            ReasonCode.RAW_OCR_DIVERGENCE.value: "raw PDF text differs from visual OCR",
            ReasonCode.CROSS_DOCUMENT_REUSE.value: "cross-document template reuse",
            ReasonCode.DEVICE_CLONE.value: "device fingerprint cloning detected",
            ReasonCode.IMPOSSIBLE_TRAVEL.value: "impossible geographic travel velocity",
            ReasonCode.VPN_DETECTED.value: "VPN/Tor/Proxy network detected",
            ReasonCode.SCRIPTED_SUBMISSION.value: "scripted or automated submission",
            ReasonCode.KNOWN_DEVICE_CLUSTER.value: "known device fraud cluster",
            ReasonCode.REPEATED_PATTERN.value: "repeated fraud pattern detected",
            ReasonCode.PAN_NAME_MISMATCH.value: "PAN card identity name mismatch",
            ReasonCode.COMPANY_NOT_FOUND.value: "employer company not found in registry",
            ReasonCode.IFSC_INVALID.value: "invalid bank IFSC code",
            ReasonCode.BANK_ACCOUNT_MISMATCH.value: "bank account beneficiary name mismatch",
            ReasonCode.GST_STATE_CODE_INVALID.value: "GST state code prefix invalid",
            ReasonCode.GSTIN_FORMAT_INVALID.value: "GSTIN format invalid",
            ReasonCode.CIN_FORMAT_INVALID.value: "CIN format invalid",
            ReasonCode.GSTIN_PAN_MISMATCH.value: "PAN embedded in GSTIN mismatch",
            ReasonCode.DUPLICATE_DOCUMENT.value: "duplicate document upload detected",
            ReasonCode.SIMILAR_DOCUMENT_FOUND.value: "highly similar document layout found",
            ReasonCode.BILL_CONSUMER_MISMATCH.value: "utility bill consumer name mismatch",
            ReasonCode.BILL_STALE.value: "stale utility bill",
            ReasonCode.BILL_MATH_MISMATCH.value: "utility bill charges arithmetic mismatch",
            ReasonCode.TAX_MATH_MISMATCH.value: "tax calculation arithmetic mismatch",
        }
        readable = [labels.get(reason, reason.lower()) for reason in reasons[:3]]
        return "Document flagged due to " + ", ".join(readable) + "."
    if ocr_warnings:
        return "Document processed with low OCR confidence; manual review is recommended but no fraud signal fired."
    if state == RiskState.LOW:
        return "Document appears consistent across available metadata, OCR, seal, and semantic checks."
    return "Document requires review based on available risk signals."


def _path_from_url_hint(base_dir: Path, doc_id: str, _url: Optional[str]) -> Optional[str]:
    if not _url:
        return None
    matches = list(base_dir.glob(f"{doc_id}*_seal.png"))
    return str(matches[0]) if matches else None
