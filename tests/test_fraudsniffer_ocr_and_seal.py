from pathlib import Path

import pytest
from PIL import Image, ImageDraw

from fraudsniffer.models import FeatureStatus
from fraudsniffer.ocr import run_payslip_ocr
from fraudsniffer.seal_phash import analyze_seal, ensure_reference_seal


def test_ocr_missing_fields_are_unavailable_without_fraud_penalty(tmp_path):
    doc = tmp_path / "payslip.txt"
    doc.write_text("This document is too blurry for OCR.", encoding="utf-8")

    result = run_payslip_ocr(doc, {"doc_type": "PAYSLIP", "ocr_confidence": 0.4})

    assert result.fields["salary_amount"].status == FeatureStatus.UNAVAILABLE
    assert result.fields["employer_name"].status == FeatureStatus.UNAVAILABLE
    assert result.ocr_confidence is None
    assert result.warnings == ["OCR EXTRACTION FAILED \u2014 MANUAL REVIEW REQUIRED"]


def test_low_ocr_confidence_warns_without_marking_fields_unavailable(tmp_path):
    doc = tmp_path / "payslip.txt"
    doc.write_text(
        "Employee Name: Priya Rao\nEmployer: Canara Tech\nSalary: 48000\nDate: 2026-05-01",
        encoding="utf-8",
    )

    result = run_payslip_ocr(doc, {"doc_type": "PAYSLIP", "ocr_confidence": 0.55})

    assert result.fields["salary_amount"].status == FeatureStatus.REAL
    assert result.ocr_confidence == 0.55
    assert "LOW OCR CONFIDENCE" in result.warnings[0]


def test_ocr_extracts_unlabeled_company_extended_fields_and_masked_account(tmp_path):
    doc = tmp_path / "skyline_payslip.txt"
    doc.write_text(
        "\n".join(
            [
                "SALARY SLIP - APRIL 2026",
                "SKYLINE INFRASTRUCTURE PRIVATE LIMITED",
                "Registered Office: No. 42, MG Road, Bengaluru - 560001",
                "Employee Name: Rahul Verma",
                "Employee ID: EMP-48291",
                "Designation: Junior Sales Executive",
                "Department: Field Operations",
                "Pay Period: April 2026",
                "Date of Issue: 04 April 2026",
                "Gross Earnings: Rs. 4,75,000",
                "NET PAY: Rs. 4,69,500",
                "Bank Account: XXXX XXXX 4817",
                "IFSC: HDFC0002145",
            ]
        ),
        encoding="utf-8",
    )

    result = run_payslip_ocr(doc, {"doc_type": "PAYSLIP"})

    assert result.fields["employer_name"].value == "SKYLINE INFRASTRUCTURE PRIVATE LIMITED"
    assert result.fields["company_name"].value == "SKYLINE INFRASTRUCTURE PRIVATE LIMITED"
    assert result.fields["date"].value == "04 April 2026"
    assert result.fields["date_of_issue"].value == "04 April 2026"
    assert result.fields["employee_id"].value == "EMP-48291"
    assert result.fields["department"].value == "Field Operations"
    assert result.fields["bank_account"].value == "XXXX XXXX 4817"


def test_seal_phash_real_when_crop_succeeds(tmp_path):
    reference = ensure_reference_seal(tmp_path / "reference.png")
    # Pad the file to make it > 5000 bytes so it is treated as a real reference seal
    with open(reference, "ab") as f:
        f.write(b"\0" * 6000)
    doc = tmp_path / "doc.png"
    canvas = Image.new("RGB", (500, 500), "white")
    seal = Image.open(reference).convert("RGB").resize((120, 120))
    canvas.paste(seal, (340, 340))
    draw = ImageDraw.Draw(canvas)
    draw.text((30, 30), "PAYSLIP", fill="black")
    canvas.save(doc)

    evidence = analyze_seal(
        doc,
        {"seal_bbox": [340, 340, 460, 460]},
        tmp_path / "seals",
        reference,
    )

    assert evidence.feature_status == FeatureStatus.REAL
    assert evidence.raw_hamming_distance is not None
    assert evidence.seal_phash_distance is not None
    assert Path(evidence.extracted_seal_path).exists()


def test_pdf_seal_extraction_uses_page_marker_instead_of_blank_crop(tmp_path):
    fitz = pytest.importorskip("fitz", reason="PyMuPDF required for PDF seal test")
    reference = ensure_reference_seal(tmp_path / "reference.png")
    # Pad the file to make it > 5000 bytes so it is treated as a real reference seal
    with open(reference, "ab") as f:
        f.write(b"\0" * 6000)
    pdf_path = tmp_path / "marker_on_page_two.pdf"

    doc = fitz.open()
    page_one = doc.new_page(width=595, height=842)
    page_one.insert_text((72, 72), "SALARY SLIP", fontsize=14)
    page_two = doc.new_page(width=595, height=842)
    page_two.insert_text((72, 120), "Authorized Signatory", fontsize=10)
    page_two.insert_text((72, 145), "HR Payroll Division", fontsize=10)
    page_two.insert_text((72, 175), "[Company Seal]", fontsize=14)
    doc.save(str(pdf_path))
    doc.close()

    evidence = analyze_seal(pdf_path, {}, tmp_path / "seals", reference)

    assert evidence.feature_status == FeatureStatus.REAL
    assert "page 2" in evidence.evidence
    extracted_path = Path(evidence.extracted_seal_path)
    assert extracted_path.exists()
    extracted = Image.open(extracted_path).convert("L")
    assert extracted.getextrema()[0] < 245


def test_seal_unavailable_for_non_image_document(tmp_path):
    doc = tmp_path / "doc.txt"
    doc.write_text("no image here", encoding="utf-8")

    evidence = analyze_seal(doc, {}, tmp_path / "seals", tmp_path / "reference.png")

    assert evidence.feature_status == FeatureStatus.UNAVAILABLE
    assert evidence.seal_phash_distance is None
