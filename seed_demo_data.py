#!/usr/bin/env python
"""
Seed Script for FraudSniffer Demo Data

This script initializes a fresh local database and populates it with a variety of
realistic payslip documents (clean, outlier, backdated, arithmetic mismatch, behavioral VPN).
It runs them through the actual FraudSniffer processing pipeline to build realistic
PQC-signed ledger entries, and inserts mock underwriter reviews.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from fraudsniffer.pipeline import FraudSnifferService
from fraudsniffer.models import TelemetryData


def clear_existing_data(data_dir: Path) -> None:
    print("Clearing existing demo data...")
    # Delete DB
    db_file = data_dir / "fraudsniffer.db"
    if db_file.exists():
        os.remove(db_file)
        print(f"  Removed database: {db_file}")

    # Delete PQC logs
    pqc_dir = data_dir / "pqc_logs"
    if pqc_dir.exists():
        shutil.rmtree(pqc_dir)
        print(f"  Removed PQC audit logs: {pqc_dir}")

    # Delete originals, annotated, seals, forensics
    for sub in ("originals", "annotated", "seals", "forensics"):
        path = data_dir / "documents" / sub
        if path.exists():
            shutil.rmtree(path)
            print(f"  Cleaned documents subdirectory: {path}")


def create_temp_payslip(path: Path, content: str) -> None:
    path.write_text(content.strip(), encoding="utf-8")


def main() -> None:
    data_dir = Path("data").resolve()
    clear_existing_data(data_dir)

    print("\nInitializing FraudSniffer Service...")
    service = FraudSnifferService(root_dir=data_dir)

    temp_dir = data_dir / "temp_mock_docs"
    temp_dir.mkdir(parents=True, exist_ok=True)

    try:
        # ── 1. SEED HISTORICAL NORMAL SALARIES (for Z-Score Base line) ─────────────────
        # We seed 5 normal salaries for "Skyline Infrastructure Pvt Ltd" (avg ~ 35,000)
        # to ensure that the z-score calculations work and flag the upcoming outlier.
        print("\nSeeding 5 historical cases for Z-Score baseline...")
        for i in range(1, 6):
            doc_path = temp_dir / f"hist_skyline_{i}.txt"
            salary = 30000 + (i * 2000)
            create_temp_payslip(
                doc_path,
                f"""
                SALARY SLIP - APRIL 2026
                Skyline Infrastructure Pvt Ltd
                Employee Name: Employee {i}
                Employee ID: EMP-100{i}
                Designation: Sales Executive
                Gross Earnings: Rs. {salary + 3000}
                Total Deductions: Rs. 3000
                NET PAY: Rs. {salary}
                Date of Issue: 30 April 2026
                """
            )
            service.process_file(
                doc_path,
                {
                    "doc_type": "PAYSLIP",
                    "job_title": "Sales Executive",
                    "employer_name": "Skyline Infrastructure Pvt Ltd",
                    "employee_name": f"Employee {i}",
                    "salary_amount": salary,
                },
                doc_id=f"doc_hist_skyline_{i}"
            )
            # Submit review to finalize
            service.save_review(
                doc_id=f"doc_hist_skyline_{i}",
                review_notes="Automated seed baseline",
                reviewed_by="system",
                manual_verdict="APPROVE"
            )

        # ── 2. SEED ACTIVE MOCK CASES ──────────────────────────────────────────────────
        print("\nProcessing Active Demo Cases...")

        # --- Case 1: Clean Payslip (Low Risk) ---
        print("  - Processing Case 1: Clean Payslip (Low Risk)...")
        case1_path = temp_dir / "payslip_priya_rao.txt"
        create_temp_payslip(
            case1_path,
            """
            SALARY SLIP - MAY 2026
            Canara Tech Solutions Private Limited
            Employee Name: Priya Rao
            Employee ID: EMP-10492
            Designation: Software Engineer
            Gross Earnings: Rs. 1,50,000.00
            Total Deductions: Rs. 15,000.00
            NET PAY: Rs. 1,35,000.00
            Date of Issue: 31 May 2026
            Bank Account: 1209384019
            IFSC: CNRB0001092
            """
        )
        service.process_file(
            case1_path,
            {
                "doc_type": "PAYSLIP",
                "loan_amount": 1000000,
                "job_title": "Software Engineer",
                "employee_name": "Priya Rao",
                "employer_name": "Canara Tech Solutions Private Limited",
                "salary_amount": 135000,
            },
            doc_id="doc_demo_clean"
        )
        service.save_review("doc_demo_clean", "Verified details via corporate callback. Approved.", "underwriter_1", "APPROVE")

        # --- Case 2: Salary Mismatch & Outlier (Suspect Risk) ---
        print("  - Processing Case 2: Salary Band & Z-Score Mismatch (Suspect)...")
        case2_path = temp_dir / "payslip_rahul_verma.txt"
        create_temp_payslip(
            case2_path,
            """
            SALARY SLIP - MAY 2026
            Skyline Infrastructure Pvt Ltd
            Employee Name: Rahul Verma
            Employee ID: EMP-7234
            Designation: Junior Sales Executive
            Gross Earnings: Rs. 4,75,000.00
            Total Deductions: Rs. 5,500.00
            NET PAY: Rs. 4,69,500.00
            Date of Issue: 31 May 2026
            """
        )
        # Designation is "Junior Sales Executive" but Net Pay is Rs. 4,69,500
        service.process_file(
            case2_path,
            {
                "doc_type": "PAYSLIP",
                "loan_amount": 5000000,
                "job_title": "Junior Sales Executive",
                "employee_name": "Rahul Verma",
                "employer_name": "Skyline Infrastructure Pvt Ltd",
                "salary_amount": 469500,
            },
            doc_id="doc_demo_mismatch"
        )
        service.save_review("doc_demo_mismatch", "Flagged. Salary is anomalous for Junior role ($469k vs baseline max $60k).", "underwriter_2", "REJECT")

        # --- Case 3: Metadata Backdated (Watch Risk) ---
        print("  - Processing Case 3: Backdated PDF Metadata (Watch)...")
        case3_path = temp_dir / "payslip_backdated.txt"
        create_temp_payslip(
            case3_path,
            """
            SALARY SLIP - JANUARY 2026
            Canara Tech Solutions Private Limited
            Employee Name: Priya Rao
            Employee ID: EMP-10492
            Designation: Software Engineer
            Gross Earnings: Rs. 1,50,000.00
            Total Deductions: Rs. 15,000.00
            NET PAY: Rs. 1,35,000.00
            Date of Issue: 31 January 2026
            """
        )
        service.process_file(
            case3_path,
            {
                "doc_type": "PAYSLIP",
                "loan_amount": 1000000,
                "claimed_document_date": "2026-01-31",
                "pdf_created_date": "2026-05-15",  # Delta of 104 days
            },
            doc_id="doc_demo_backdated"
        )

        # --- Case 4: Arithmetic Mismatch (Watch Risk) ---
        print("  - Processing Case 4: Table Arithmetic Inconsistency (Watch)...")
        case4_path = temp_dir / "payslip_arithmetic.txt"
        create_temp_payslip(
            case4_path,
            """
            SALARY SLIP - MAY 2026
            Canara Tech Solutions Private Limited
            Employee Name: Priya Rao
            Employee ID: EMP-10492
            Designation: Software Engineer
            Gross Earnings: Rs. 1,50,000.00
            Total Deductions: Rs. 15,000.00
            NET PAY: Rs. 95,000.00
            Date of Issue: 31 May 2026
            """
        )
        # Gross (150,000) - Deductions (15,000) = 135,000 but Net is 95,000
        service.process_file(
            case4_path,
            {
                "doc_type": "PAYSLIP",
                "loan_amount": 1000000,
            },
            doc_id="doc_demo_arithmetic"
        )

        # --- Case 5: Behavioral VPN Alert (Suspect Risk) ---
        print("  - Processing Case 5: VPN Submission (Suspect)...")
        case5_path = temp_dir / "payslip_vpn.txt"
        create_temp_payslip(
            case5_path,
            """
            SALARY SLIP - MAY 2026
            Canara Tech Solutions Private Limited
            Employee Name: Priya Rao
            Employee ID: EMP-10492
            Designation: Software Engineer
            Gross Earnings: Rs. 1,50,000.00
            Total Deductions: Rs. 15,000.00
            NET PAY: Rs. 1,35,000.00
            Date of Issue: 31 May 2026
            """
        )
        telemetry = TelemetryData(
            canvas_fingerprint="fingerprint_abc123xyz",
            ip_address="185.200.118.4",  # Tor/VPN Exit node range
            vpn_detected=True,
            proxy_detected=False,
            tor_detected=False,
            keystroke_duration_ms=450,
            submission_duration_ms=2500,
        )
        service.process_file(
            case5_path,
            {
                "doc_type": "PAYSLIP",
                "loan_amount": 1000000,
            },
            doc_id="doc_demo_vpn",
            telemetry=telemetry
        )

        print("\nSeeding completed successfully!")
        print("----------------------------------------------------------------------")
        print("Active seeded cases in dashboard:")
        print("  1. doc_demo_clean      -> Clean Document (Approved, Low Risk)")
        print("  2. doc_demo_mismatch   -> Outlier & Mismatch (Rejected, Suspect Risk)")
        print("  3. doc_demo_backdated  -> Backdated metadata (Needs Review, Watch Risk)")
        print("  4. doc_demo_arithmetic  -> Arithmetic mismatch (Needs Review, Watch Risk)")
        print("  5. doc_demo_vpn         -> VPN behavioral alert (Needs Review, Suspect Risk)")
        print("----------------------------------------------------------------------")
        print("To start the app, run:")
        print("  .\\start_fraud_sniffer.ps1")

    finally:
        # Clean up temporary documents folder
        if temp_dir.exists():
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    main()
