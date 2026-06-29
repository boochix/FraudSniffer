from PIL import Image

from fraudsniffer.models import ReasonCode
from fraudsniffer.pipeline import FraudSnifferService
from fraudsniffer.seal_phash import ensure_reference_seal
from fraudsniffer.web_app import create_app


def _make_doc_with_seal(path, reference):
    canvas = Image.new("RGB", (500, 500), "white")
    seal = Image.open(reference).convert("RGB").resize((120, 120))
    canvas.paste(seal, (340, 340))
    canvas.save(path)


def test_pipeline_finalizes_when_ocr_fields_are_missing(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    doc = tmp_path / "bad_ocr.txt"
    doc.write_text("blurred scan", encoding="utf-8")

    risk = service.process_file(
        doc,
        {
            "doc_type": "PAYSLIP",
            "loan_amount": 2_000_000,
            "job_title": "Software Engineer",
        },
        doc_id="doc_bad_ocr",
    )
    data = risk.to_dict()

    assert data["pipeline_state"] == "FINALIZED"
    assert data["feature_status"]["salary_amount"] == "UNAVAILABLE"
    assert ReasonCode.SALARY_OUTLIER.value not in data["risk_decision_reason_codes"]
    assert data["processing_time_ms"] is not None


def test_pipeline_emits_seal_mismatch_reason_for_real_phash(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    reference = ensure_reference_seal(service.reference_seal_path)
    # Pad the file to make it > 5000 bytes so it is treated as a real reference seal
    with open(reference, "ab") as f:
        f.write(b"\0" * 6000)
    doc = tmp_path / "seal_doc.png"
    _make_doc_with_seal(doc, reference)
    # Draw over the pasted seal to force a real mismatch.
    image = Image.open(doc).convert("RGB")
    for x in range(360, 440):
        for y in range(360, 440):
            image.putpixel((x, y), (220, 20, 60))
    image.save(doc)

    risk = service.process_file(
        doc,
        {
            "doc_type": "PAYSLIP",
            "ocr_text": "Employee Name: Priya Rao\nEmployer: Canara Tech\nSalary: 48000\nDate: 2026-05-01",
            "loan_amount": 500_000,
            "job_title": "Software Engineer",
            "seal_bbox": [340, 340, 460, 460],
        },
        doc_id="doc_seal",
    )
    data = risk.to_dict()

    assert data["feature_status"]["seal_phash_distance"] == "REAL"
    assert data["seal_evidence"]["raw_hamming_distance"] is not None
    assert data["artifacts"]["annotated_file_url"].endswith("/annotated")


def test_pipeline_exposes_extended_ocr_values_in_result_json(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    doc = tmp_path / "skyline_payslip.txt"
    doc.write_text(
        "\n".join(
            [
                "SALARY SLIP - APRIL 2026",
                "SKYLINE INFRASTRUCTURE PRIVATE LIMITED",
                "Employee Name: Rahul Verma",
                "Employee ID: EMP-48291",
                "Designation: Junior Sales Executive",
                "Department: Field Operations",
                "Pay Period: April 2026",
                "Date of Issue: 04 April 2026",
                "Gross Earnings: Rs. 4,75,000",
                "Total Deductions: Rs. 5,500",
                "NET PAY: Rs. 4,69,500",
                "Bank Account: XXXX XXXX 4817",
                "IFSC: HDFC0002145",
            ]
        ),
        encoding="utf-8",
    )

    risk = service.process_file(doc, {"doc_type": "PAYSLIP"}, doc_id="doc_skyline_fields")
    data = risk.to_dict()

    assert data["feature_status"]["employer_name"] == "REAL"
    assert data["feature_status"]["company_name"] == "REAL"
    assert data["feature_values"]["employer_name"] == "SKYLINE INFRASTRUCTURE PRIVATE LIMITED"
    assert data["feature_values"]["company_name"] == "SKYLINE INFRASTRUCTURE PRIVATE LIMITED"
    assert data["feature_values"]["date_of_issue"] == "04 April 2026"
    assert data["feature_values"]["employee_id"] == "EMP-48291"
    assert data["feature_values"]["department"] == "Field Operations"
    assert data["feature_values"]["bank_account"] == "XXXX XXXX 4817"
    assert data["semantic_check"]["reason_code"] == ReasonCode.SEMANTIC_INCOHERENCE.value


def test_api_key_protects_api_routes(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    app = create_app(service, api_key="secret")
    client = app.test_client()

    response = client.get("/api/documents/missing/risk")
    assert response.status_code == 401

    response = client.get("/api/documents/missing/risk", headers={"X-API-Key": "secret"})
    assert response.status_code == 404


def test_review_endpoint_persists_underwriter_override(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    app = create_app(service, api_key="secret")
    client = app.test_client()

    response = client.post(
        "/api/reviews/doc_1",
        headers={"X-API-Key": "secret"},
        json={
            "review_notes": "Approved after employer callback.",
            "reviewed_by": "underwriter_7",
            "manual_verdict": "APPROVE",
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["manual_verdict"] == "APPROVE"


def test_pipeline_unhandled_exception_records_error_state(tmp_path):
    import pytest
    from unittest.mock import patch
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    doc = tmp_path / "test.txt"
    doc.write_text("dummy content", encoding="utf-8")
    
    with patch("fraudsniffer.pipeline.extract_features", side_effect=ValueError("Tesseract crash")):
        with pytest.raises(ValueError, match="Tesseract crash"):
            service.process_file(doc, {"doc_type": "PAYSLIP"}, doc_id="doc_fail")
            
    # Verify the database state is ERROR
    timeline = service.storage.get_timeline("doc_fail")
    assert any(event["state"] == "ERROR" and "Tesseract crash" in event["error_message"] for event in timeline)
    
    with service.storage._connect() as conn:
        row = conn.execute("SELECT pipeline_state FROM documents WHERE doc_id = 'doc_fail'").fetchone()
        assert row["pipeline_state"] == "ERROR"


def test_rate_limiting_on_submit(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    app = create_app(service)
    client = app.test_client()
    
    import io
    # Send 10 successful requests
    for i in range(10):
        response = client.post(
            "/api/documents/submit",
            data={
                "file": (io.BytesIO(b"file content"), "payslip.txt"),
                "metadata": "{}",
            }
        )
        assert response.status_code == 200
        
    # The 11th should be rate-limited (429)
    response = client.post(
        "/api/documents/submit",
        data={
            "file": (io.BytesIO(b"file content"), "payslip.txt"),
            "metadata": "{}",
        }
    )
    assert response.status_code == 429
    assert "rate limit exceeded" in response.get_json()["error"]


def test_max_content_length(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    app = create_app(service)
    assert app.config["MAX_CONTENT_LENGTH"] == 16 * 1024 * 1024
