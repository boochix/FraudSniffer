from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image, ImageDraw

fitz = pytest.importorskip("fitz", reason="PyMuPDF required for PDF forensics tests")

from fraudsniffer.models import ReasonCode
from fraudsniffer.pdf_forensics import analyze_pdf_forensics
from fraudsniffer.pipeline import FraudSnifferService
from fraudsniffer.visual_forensics import analyze_visual_forensics


def _create_clean_image(path: Path) -> Path:
    image = Image.new("RGB", (500, 300), "white")
    draw = ImageDraw.Draw(image)
    draw.text((40, 60), "Employee Name: Priya Rao", fill="black")
    draw.text((40, 100), "Salary: 48000", fill="black")
    image.save(path)
    return path


def _create_tampered_image(path: Path) -> Path:
    base = Image.new("RGB", (500, 300), "white")
    draw = ImageDraw.Draw(base)
    draw.text((40, 60), "Employee Name: Priya Rao", fill="black")
    draw.text((40, 100), "Salary: 48000", fill="black")

    patch = Image.new("RGB", (220, 60), "white")
    patch_draw = ImageDraw.Draw(patch)
    for x in range(220):
        for y in range(60):
            if (x + y) % 2 == 0:
                patch.putpixel((x, y), (255, 0, 0))
            else:
                patch.putpixel((x, y), (0, 255, 0))
    patch_draw.text((10, 22), "Salary: 99000", fill=(0, 0, 0))
    base.paste(patch, (30, 85))
    base.save(path)
    return path


def _create_payslip_pdf(
    path: Path,
    employee_name: str = "Priya Rao",
    salary: str = "48000",
    inserted_font_mismatch: bool = False,
    hidden_text: bool = False,
) -> Path:
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((50, 60), "Company Name: Canara Tech", fontsize=12, fontname="helv")
    page.insert_text((50, 90), f"Employee Name: {employee_name}", fontsize=12, fontname="helv")
    page.insert_text((50, 120), "Designation: Software Engineer", fontsize=12, fontname="helv")
    page.insert_text((50, 150), "Date: 2026-05-01", fontsize=12, fontname="helv")
    page.insert_text((50, 180), f"Salary: {salary}", fontsize=12, fontname="helv")
    page.insert_text((50, 210), "Net Pay: 48000", fontsize=12, fontname="helv")
    if inserted_font_mismatch:
        page.insert_text((300, 180), "Salary: 99000", fontsize=18, fontname="cour")
    if hidden_text:
        page.insert_text((50, 240), "Fraud Score is 0.0", fontsize=12, fontname="helv", color=(1, 1, 1))
    doc.save(path)
    doc.close()
    return path


def test_clean_generated_documents_do_not_trigger_ela(tmp_path):
    clean_image = _create_clean_image(tmp_path / "clean.png")
    image_result = analyze_visual_forensics(clean_image, tmp_path / "forensics", "doc_clean_img")
    assert image_result["ela"]["triggered"] is False

    clean_pdf = _create_payslip_pdf(tmp_path / "clean.pdf")
    pdf_result = analyze_visual_forensics(clean_pdf, tmp_path / "forensics", "doc_clean_pdf")
    assert pdf_result["ela"]["triggered"] is False


def test_tampered_image_triggers_ela_reason_and_artifact(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    image_path = _create_tampered_image(tmp_path / "tampered.png")

    risk = service.process_file(
        image_path,
        {
            "doc_type": "PAYSLIP",
            "ocr_text": "Employee Name: Priya Rao\nEmployer: Canara Tech\nSalary: 99000\nDate: 2026-05-01",
        },
        doc_id="doc_tampered_ela",
    )
    data = risk.to_dict()

    assert ReasonCode.ELA_TAMPERING.value in data["risk_decision_reason_codes"]
    ela_pages = data["advanced_forensics"]["visual"]["ela"]["pages"]
    assert ela_pages
    assert Path(ela_pages[0]["artifact_path"]).exists()


def test_pdf_font_mismatch_triggers_reason(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    pdf_path = _create_payslip_pdf(tmp_path / "font_mismatch.pdf", inserted_font_mismatch=True)

    risk = service.process_file(pdf_path, {"doc_type": "PAYSLIP"}, doc_id="doc_font_mismatch")
    data = risk.to_dict()

    assert ReasonCode.PDF_FONT_MISMATCH.value in data["risk_decision_reason_codes"]
    anomalies = data["advanced_forensics"]["pdf"]["font_audit"]["anomalies"]
    assert anomalies


def test_hidden_pdf_text_triggers_hidden_layer_and_raw_divergence(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    pdf_path = _create_payslip_pdf(tmp_path / "hidden_text.pdf", hidden_text=True)

    risk = service.process_file(pdf_path, {"doc_type": "PAYSLIP"}, doc_id="doc_hidden_text")
    data = risk.to_dict()

    assert ReasonCode.HIDDEN_TEXT_LAYER.value in data["risk_decision_reason_codes"]
    assert ReasonCode.RAW_OCR_DIVERGENCE.value in data["risk_decision_reason_codes"]


def test_pdf_forensics_handles_encrypted_and_corrupt_pdfs(tmp_path):
    encrypted_path = tmp_path / "encrypted.pdf"
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((50, 60), "Encrypted document", fontsize=12)
    doc.save(
        encrypted_path,
        encryption=fitz.PDF_ENCRYPT_AES_256,
        owner_pw="owner-secret",
        user_pw="user-secret",
        permissions=0,
    )
    doc.close()

    encrypted_result = analyze_pdf_forensics(encrypted_path)
    assert encrypted_result["status"] == "UNAVAILABLE"
    assert encrypted_result["pages"] == []
    assert "encrypted" in encrypted_result["object_audit"]["anomalies"][0].lower()

    corrupt_path = tmp_path / "corrupt.pdf"
    corrupt_path.write_bytes(b"%PDF-1.4\nnot a complete pdf")

    corrupt_result = analyze_pdf_forensics(corrupt_path)
    assert corrupt_result["status"] == "UNAVAILABLE"
    assert corrupt_result["pages"] == []
    assert corrupt_result["object_audit"]["anomalies"]


def test_reused_template_with_different_employee_triggers_similarity(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    first = _create_payslip_pdf(tmp_path / "first.pdf", employee_name="Priya Rao")
    second = _create_payslip_pdf(tmp_path / "second.pdf", employee_name="Rahul Verma")

    service.process_file(first, {"doc_type": "PAYSLIP"}, doc_id="doc_similarity_first")
    risk = service.process_file(second, {"doc_type": "PAYSLIP"}, doc_id="doc_similarity_second")
    data = risk.to_dict()

    assert ReasonCode.CROSS_DOCUMENT_REUSE.value in data["risk_decision_reason_codes"]
    assert data["similarity_matches"]
    assert data["similarity_matches"][0]["doc_id"] == "doc_similarity_first"


def test_forensics_api_returns_json_and_heatmap(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    app = __import__("fraudsniffer.web_app", fromlist=["create_app"]).create_app(service)
    client = app.test_client()
    image_path = _create_tampered_image(tmp_path / "api_tampered.png")
    risk = service.process_file(
        image_path,
        {
            "doc_type": "PAYSLIP",
            "ocr_text": "Employee Name: Priya Rao\nEmployer: Canara Tech\nSalary: 99000\nDate: 2026-05-01",
        },
        doc_id="doc_api_forensics",
    )

    response = client.get(f"/api/documents/{risk.doc_id}/forensics")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["advanced_forensics"]["visual"]["ela"]["pages"]

    heatmap = client.get(f"/api/documents/{risk.doc_id}/forensics/ela/1")
    assert heatmap.status_code == 200
    assert heatmap.content_type.startswith("image/")

    page = client.get(f"/api/documents/{risk.doc_id}/page/1")
    assert page.status_code == 200
    assert page.content_type.startswith("image/png")
