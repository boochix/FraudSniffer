from __future__ import annotations

import os
import pytest
from pathlib import Path
from fraudsniffer.ocr import auto_detect_document_type
from fraudsniffer.registry_verifier import verify_gst_registry, verify_cin_registry
from fraudsniffer.models import ReasonCode
from fraudsniffer.pipeline import FraudSnifferService


def test_auto_detect_document_type():
    # 1. GST Registration
    gst_text = "Goods and Services Tax Registration Certificate GSTIN 29ABCDE1234F1Z5 Form GST REG-06 Government of India"
    gst_res = auto_detect_document_type(gst_text)
    assert gst_res["document_type"] == "GST_REGISTRATION"
    assert gst_res["confidence"] >= 0.85

    # 2. Income Tax Form
    tax_text = "Income Tax Department Assessment Year 2024-25 Form No. 16 Part A Details of Tax Deducted at Source"
    tax_res = auto_detect_document_type(tax_text)
    assert tax_res["document_type"] == "INCOME_TAX_FORM"
    assert tax_res["confidence"] >= 0.80

    # 3. Company Registration
    cin_text = "Ministry of Corporate Affairs Certificate of Incorporation Corporate Identity Number U65110KA1906GOI003313 Registrar of Companies"
    cin_res = auto_detect_document_type(cin_text)
    assert cin_res["document_type"] == "COMPANY_REGISTRATION"
    assert cin_res["confidence"] >= 0.85

    # 4. Utility Bill
    bill_text = "Electricity Bill Consumer No. 123456789 Due Date 15/06/2026 Energy Charges Fixed Charges Total Amount Due"
    bill_res = auto_detect_document_type(bill_text)
    assert bill_res["document_type"] == "UTILITY_BILL"
    assert bill_res["confidence"] >= 0.80


def test_verify_gst_registry():
    # Valid GSTIN matching mock database
    res = verify_gst_registry("29ABCDE1234F1Z5", "Canara Enterprise")
    assert res["valid"] is True
    assert res["state"] == "Karnataka"
    assert res["pan"] == "ABCDE1234F"

    # Malformed GSTIN
    res_malformed = verify_gst_registry("1234", "Canara Enterprise")
    assert res_malformed["valid"] is False
    assert res_malformed["reason_code"] == "GSTIN_FORMAT_INVALID"

    # Invalid State Code
    res_state = verify_gst_registry("99ABCDE1234F1Z5", "Canara Enterprise")
    assert res_state["valid"] is False
    assert res_state["reason_code"] == "GST_STATE_CODE_INVALID"

    # Unregistered GSTIN
    res_unreg = verify_gst_registry("29XYZAB5678C1Z9", "Canara Enterprise")
    assert res_unreg["valid"] is False
    assert res_unreg["reason_code"] == "COMPANY_NOT_FOUND"


def test_verify_cin_registry():
    # Valid CIN
    res = verify_cin_registry("U65110KA1906GOI003313", "Canara Bank")
    assert res["valid"] is True
    assert res["listing_status"] == "UNLISTED"
    assert res["state"] == "KA"

    # Malformed CIN
    res_malformed = verify_cin_registry("12345", "Canara Bank")
    assert res_malformed["valid"] is False
    assert res_malformed["reason_code"] == "CIN_FORMAT_INVALID"

    # Unregistered CIN
    res_unreg = verify_cin_registry("U65110KA1906GOI999999", "Canara Bank")
    assert res_unreg["valid"] is False
    assert res_unreg["reason_code"] == "COMPANY_NOT_FOUND"


def test_pipeline_multi_document_verification(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")

    # 1. GST Registration Document processing
    doc_gst = tmp_path / "gst_cert.txt"
    doc_gst.write_text(
        "\n".join([
            "Government of India",
            "Registration Certificate Certificate of Incorporation",
            "GSTIN: 29ABCDE1234F1Z5",
            "Legal Name: Canara Verified User",
            "Trade Name: Canara Enterprise",
            "Address: Bengaluru, Karnataka",
        ]),
        encoding="utf-8"
    )

    risk = service.process_file(
        doc_gst,
        {
            "company_name": "Canara Enterprise",
            "pan_number": "ABCDE1234F"
        },
        doc_id="gst_test_doc"
    )
    data = risk.to_dict()

    # Verify serialization of classification type and confidence
    assert data["document_type"] == "GST_REGISTRATION"
    assert data["classification_confidence"] > 0.70

    # Verify document classified event, registry outputs and confidence
    assert data["external_verification"]["gst"]["valid"] is True
    assert ReasonCode.GST_STATE_CODE_INVALID.value not in data["risk_decision_reason_codes"]
    assert ReasonCode.GSTIN_PAN_MISMATCH.value not in data["risk_decision_reason_codes"]

    # Verify PQC event logging
    pqc_events = service.audit_trail.get_timeline_for_document("gst_test_doc")
    assert any(event["event_type"] == "DOCUMENT_CLASSIFIED" for event in pqc_events)
    classified_event = [e for e in pqc_events if e["event_type"] == "DOCUMENT_CLASSIFIED"][0]
    assert classified_event["details"]["document_type"] == "GST_REGISTRATION"
    assert classified_event["details"]["confidence"] > 0.70


def test_pipeline_gst_pan_mismatch(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    doc_gst = tmp_path / "gst_cert.txt"
    doc_gst.write_text(
        "\n".join([
            "Government of India",
            "GSTIN: 29ABCDE1234F1Z5",
            "Legal Name: Canara Verified User",
        ]),
        encoding="utf-8"
    )
    # PAN in GST is ABCDE1234F, but we declare metadata PAN is XYZDE9999Z
    risk = service.process_file(
        doc_gst,
        {
            "company_name": "Canara Enterprise",
            "pan_number": "XYZDE9999Z"
        },
        doc_id="gst_mismatch_doc"
    )
    data = risk.to_dict()
    assert ReasonCode.GSTIN_PAN_MISMATCH.value in data["risk_decision_reason_codes"]


def test_pipeline_utility_bill_staleness(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    doc_bill = tmp_path / "utility_bill.txt"
    # Create a stale bill dated in year 2020
    doc_bill.write_text(
        "\n".join([
            "Electricity Board Bill",
            "Consumer Number: 123456789",
            "Customer Name: Rahul Kumar Verma",
            "Bill Date: 2020-01-01",
            "Total Amount Due: Rs. 1,500"
        ]),
        encoding="utf-8"
    )

    risk = service.process_file(
        doc_bill,
        {
            "employee_name": "Rahul Kumar Verma"
        },
        doc_id="bill_stale_doc"
    )
    data = risk.to_dict()
    assert ReasonCode.BILL_STALE.value in data["risk_decision_reason_codes"]


def test_pipeline_duplicate_document_detection(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    doc1 = tmp_path / "doc1.txt"
    doc1.write_text("Unique text content that serves as template representation", encoding="utf-8")

    # Upload first time
    service.process_file(doc1, {"doc_type": "PAYSLIP"}, doc_id="doc_original")

    # Upload exact same content second time under different ID
    doc2 = tmp_path / "doc2.txt"
    doc2.write_text("Unique text content that serves as template representation", encoding="utf-8")
    
    risk = service.process_file(doc2, {"doc_type": "PAYSLIP"}, doc_id="doc_duplicate")
    data = risk.to_dict()

    assert ReasonCode.DUPLICATE_DOCUMENT.value in data["risk_decision_reason_codes"]


def test_api_stats(tmp_path):
    from fraudsniffer.web_app import create_app
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    app = create_app(service)
    app.testing = True
    client = app.test_client()

    # Get initial stats
    res = client.get("/api/stats")
    assert res.status_code == 200
    stats = res.get_json()
    assert stats["documents_processed"] == 0
    assert stats["duplicate_matches"] == 0

    # Insert a document
    doc = tmp_path / "doc.txt"
    doc.write_text("Goods and Services Tax Registration Certificate GSTIN 29ABCDE1234F1Z5", encoding="utf-8")
    service.process_file(doc, {"company_name": "Canara Enterprise", "pan_number": "ABCDE1234F"}, doc_id="doc1")

    # Fetch stats again
    res = client.get("/api/stats")
    assert res.status_code == 200
    stats = res.get_json()
    assert stats["documents_processed"] == 1
    assert stats["audit_events"] > 0
