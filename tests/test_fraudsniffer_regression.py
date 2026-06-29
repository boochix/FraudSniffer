"""Regression test: fake payslip must never score LOW / 0.0.

This test programmatically generates a fake Rahul Verma payslip PDF using
PyMuPDF and runs it through the full FraudSniffer pipeline, verifying that
OCR extraction, scoring, and artifact generation all work correctly.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

fitz = pytest.importorskip("fitz", reason="PyMuPDF required for regression test")

from fraudsniffer.models import FeatureStatus, RiskState
from fraudsniffer.pipeline import FraudSnifferService


def _create_fake_payslip_pdf(path: Path) -> Path:
    """Generate a realistic fake payslip PDF that should trigger fraud signals."""
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)  # A4

    # Company header
    page.insert_text((50, 60), "Skyline Infrastructure Pvt Ltd", fontsize=16)
    page.insert_text((50, 80), "Company Name: Skyline Infrastructure Pvt Ltd", fontsize=10)
    page.insert_text((50, 95), "Address: 123 MG Road, Bengaluru 560001", fontsize=9)

    # Payslip title
    page.insert_text((200, 130), "SALARY SLIP", fontsize=14)
    page.insert_text((180, 150), "Pay Period: May 2026", fontsize=10)

    # Employee details
    page.insert_text((50, 190), "Employee Name: Rahul Verma", fontsize=11)
    page.insert_text((50, 210), "Designation: Junior Sales Executive", fontsize=11)
    page.insert_text((50, 230), "Employee ID: EMP-7234", fontsize=10)
    page.insert_text((50, 250), "Date: 01-05-2026", fontsize=10)
    page.insert_text((50, 270), "Department: Sales", fontsize=10)

    # Earnings table
    page.insert_text((50, 310), "EARNINGS", fontsize=12)
    page.insert_text((50, 335), "Basic Salary", fontsize=10)
    page.insert_text((350, 335), "Rs. 2,50,000", fontsize=10)
    page.insert_text((50, 355), "HRA", fontsize=10)
    page.insert_text((350, 355), "Rs. 1,25,000", fontsize=10)
    page.insert_text((50, 375), "Special Allowance", fontsize=10)
    page.insert_text((350, 375), "Rs. 1,00,000", fontsize=10)

    page.insert_text((50, 405), "Gross Earnings: Rs. 4,75,000", fontsize=11)

    # Deductions
    page.insert_text((50, 440), "DEDUCTIONS", fontsize=12)
    page.insert_text((50, 465), "PF", fontsize=10)
    page.insert_text((350, 465), "Rs. 3,000", fontsize=10)
    page.insert_text((50, 485), "Professional Tax", fontsize=10)
    page.insert_text((350, 485), "Rs. 2,500", fontsize=10)

    # Net pay
    page.insert_text((50, 525), "Net Pay: Rs. 4,69,500", fontsize=12)

    # Seal area (simulated)
    rect = fitz.Rect(400, 650, 550, 750)
    page.draw_circle(fitz.Point(475, 700), 40, color=(0.1, 0.3, 0.7), width=2)
    page.insert_text((445, 695), "COMPANY", fontsize=8)
    page.insert_text((455, 710), "SEAL", fontsize=8)

    doc.save(str(path))
    doc.close()
    return path


def test_fake_payslip_does_not_score_low(tmp_path):
    """Core regression: a fake payslip with suspicious fields MUST NOT score LOW."""
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")

    # Generate the fake PDF
    pdf_path = tmp_path / "fake_payslip_rahul_verma.pdf"
    _create_fake_payslip_pdf(pdf_path)
    assert pdf_path.exists(), "Failed to create test PDF"

    # Process through the full pipeline
    risk = service.process_file(
        pdf_path,
        {
            "doc_type": "PAYSLIP",
            "job_title": "Software Engineer",  # Mismatch with PDF designation
            "loan_amount": 5_000_000,
            "employee_name": "Someone Else",  # Mismatch with PDF name
            "city": "Bengaluru",
            "employment_duration": 3,
            "claimed_document_date": "2026-05-01",
            "pdf_created_date": "2026-05-01",
        },
        doc_id="doc_regression_rahul",
    )
    data = risk.to_dict()

    # --- Critical assertions ---
    # 1. Score must be non-zero
    assert data["fraud_score"] > 0, (
        f"fraud_score is {data['fraud_score']}, expected > 0. "
        f"Reasons: {data['risk_decision_reason_codes']}"
    )

    # 2. State must NOT be LOW
    assert data["state"] != "LOW", (
        f"state is LOW, expected WATCH/SUSPECT/BLOCK. "
        f"Score: {data['fraud_score']}, Reasons: {data['risk_decision_reason_codes']}"
    )

    # 3. Pipeline must have finalized
    assert data["pipeline_state"] == "FINALIZED"


def test_ocr_extracts_core_fields_from_pdf(tmp_path):
    """Verify OCR correctly extracts employee name, salary, employer from the PDF."""
    from fraudsniffer.ocr import run_payslip_ocr

    pdf_path = tmp_path / "test_ocr.pdf"
    _create_fake_payslip_pdf(pdf_path)

    result = run_payslip_ocr(pdf_path, {"doc_type": "PAYSLIP"})

    # Employee name must be extracted
    assert result.fields["employee_name"].status == FeatureStatus.REAL, (
        f"employee_name status is {result.fields['employee_name'].status}, "
        f"OCR text preview: {result.text[:300]}"
    )
    assert "rahul" in str(result.fields["employee_name"].value).lower()

    # Salary must be extracted
    assert result.fields["salary_amount"].status == FeatureStatus.REAL, (
        f"salary_amount status is {result.fields['salary_amount'].status}"
    )
    assert result.fields["salary_amount"].value is not None
    assert result.fields["salary_amount"].value > 0

    # Parse coverage must be non-zero
    from fraudsniffer.ocr import PAYSLIP_CORE_FIELDS
    core_extracted = sum(
        1 for name in PAYSLIP_CORE_FIELDS
        if result.fields.get(name) and result.fields[name].status == FeatureStatus.REAL
    )
    assert core_extracted > 0, "No core fields extracted"


def test_original_and_annotated_files_exist_after_processing(tmp_path):
    """Verify both original PDF copy and annotated PNG exist on disk."""
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")

    pdf_path = tmp_path / "test_artifacts.pdf"
    _create_fake_payslip_pdf(pdf_path)

    risk = service.process_file(
        pdf_path,
        {"doc_type": "PAYSLIP"},
        doc_id="doc_artifacts_test",
    )

    # Check original PDF was persisted
    original_dir = tmp_path / "data" / "documents" / "originals"
    originals = list(original_dir.glob("doc_artifacts_test*"))
    assert len(originals) > 0, f"No original file found in {original_dir}"
    assert originals[0].exists()

    # Check annotated PNG was generated
    annotated_dir = tmp_path / "data" / "documents" / "annotated"
    annotated_files = list(annotated_dir.glob("doc_artifacts_test*"))
    assert len(annotated_files) > 0, f"No annotated file found in {annotated_dir}"
    assert annotated_files[0].exists()


def test_existing_text_file_pipeline_still_works(tmp_path):
    """Backward compatibility: text file processing must not be broken."""
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")

    txt_path = tmp_path / "payslip.txt"
    txt_path.write_text(
        "Employee Name: Priya Rao\nEmployer: Canara Tech\nSalary: 48000\nDate: 2026-05-01",
        encoding="utf-8",
    )

    risk = service.process_file(
        txt_path,
        {
            "doc_type": "PAYSLIP",
            "loan_amount": 500_000,
            "job_title": "Software Engineer",
        },
        doc_id="doc_compat_txt",
    )
    data = risk.to_dict()

    assert data["pipeline_state"] == "FINALIZED"
    assert data["feature_status"]["salary_amount"] == "REAL"
    assert data["feature_status"]["employee_name"] == "REAL"


def test_existing_image_pipeline_still_works(tmp_path):
    """Backward compatibility: image file processing must not be broken."""
    from PIL import Image, ImageDraw

    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")

    img_path = tmp_path / "payslip.png"
    img = Image.new("RGB", (400, 200), "white")
    draw = ImageDraw.Draw(img)
    draw.text((10, 10), "Employee Name: Priya Rao", fill="black")
    draw.text((10, 30), "Employer: Canara Tech", fill="black")
    draw.text((10, 50), "Salary: 48000", fill="black")
    img.save(img_path)

    risk = service.process_file(
        img_path,
        {"doc_type": "PAYSLIP"},
        doc_id="doc_compat_img",
    )
    data = risk.to_dict()

    assert data["pipeline_state"] == "FINALIZED"
    assert data["processing_time_ms"] is not None
