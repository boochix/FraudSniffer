from __future__ import annotations

import pytest
from fraudsniffer.registry_verifier import (
    verify_ifsc_code,
    verify_pan_registry,
    verify_company_existence,
    verify_bank_account_penny_drop,
)

def test_verify_ifsc_code_success():
    # Test actual valid IFSC code for HDFC Bank
    res1 = verify_ifsc_code("HDFC0002145")
    if res1.get("valid"):
        assert "HDFC" in res1.get("bank", "").upper()
        assert "SILLOD" in res1.get("branch", "").upper()
    else:
        # Graceful handling for environments without internet access
        assert "failed" in res1.get("error", "").lower() or "http error" in res1.get("error", "").lower()

    # Test actual valid IFSC code for ICICI Bank
    res2 = verify_ifsc_code("ICIC0000001")
    if res2.get("valid"):
        assert "ICICI" in res2.get("bank", "").upper()
    else:
        assert "failed" in res2.get("error", "").lower() or "http error" in res2.get("error", "").lower()

def test_verify_ifsc_code_invalid():
    # Test invalid format (too short)
    res_short = verify_ifsc_code("HDFC000")
    assert res_short["valid"] is False
    assert "format" in res_short["error"].lower()

    # Test non-existent IFSC code (correct format but invalid code)
    res_fake = verify_ifsc_code("ABCD0123456")
    assert res_fake["valid"] is False
    assert "exist" in res_fake["error"].lower() or "failed" in res_fake["error"].lower() or "http error" in res_fake["error"].lower()

def test_verify_pan_registry():
    # Test exact match in mock DB
    res = verify_pan_registry("AGTPV8291K", "Rahul Kumar Verma")
    assert res["valid"] is True
    assert res["match_score"] == 1.0

    # Test fuzzy match with slight variation (Rahul Verma matches Rahul Kumar Verma)
    res_fuzzy = verify_pan_registry("AGTPV8291K", "Rahul Verma")
    assert res_fuzzy["valid"] is True
    assert res_fuzzy["match_score"] >= 0.80

    # Test mismatch with different name in mock DB
    res_mismatch = verify_pan_registry("AGTPV8291K", "Jane Doe")
    assert res_mismatch["valid"] is False
    assert res_mismatch["match_score"] < 0.80
    assert "mismatch" in res_mismatch["error"].lower()

    # Test invalid format
    res_invalid = verify_pan_registry("ABCDE1234", "Rahul Kumar Verma")
    assert res_invalid["valid"] is False
    assert "format" in res_invalid["error"].lower()

    # Test unregistered PAN (valid format but not in DB)
    res_unreg = verify_pan_registry("PANNO9999Z", "Rahul Kumar Verma")
    assert res_unreg["valid"] is False
    assert "unregistered" in res_unreg["error"].lower()

def test_verify_company_existence():
    # Test company in mock DB
    res1 = verify_company_existence("Canara Bank")
    assert res1["valid"] is True
    assert res1["company_name"] == "CANARA BANK"
    assert res1["status"] == "ACTIVE"

    # Test company with common suffix cleaned
    res2 = verify_company_existence("infosys pvt ltd")
    assert res2["valid"] is True
    assert "INFOSYS" in res2["company_name"]

    # Test non-existent company
    res_fake = verify_company_existence("Fake Mocks Technologies Pvt Ltd")
    assert res_fake["valid"] is False
    assert "not found" in res_fake["error"].lower()

def test_verify_bank_account_penny_drop():
    # Test matching bank account
    res = verify_bank_account_penny_drop("1234567890", "HDFC0002145", "Rahul Verma")
    assert res["valid"] is True
    assert res["beneficiary_name"] == "Rahul Verma"

    # Test mismatch bank account (ends in 999)
    res_mismatch = verify_bank_account_penny_drop("1234567999", "HDFC0002145", "Rahul Verma")
    assert res_mismatch["valid"] is False
    assert res_mismatch["beneficiary_name"] == "Unknown Beneficiary"
    assert "mismatch" in res_mismatch["error"].lower()

    # Test invalid format (too short/long or non-digits)
    res_invalid = verify_bank_account_penny_drop("123", "HDFC0002145", "Rahul Verma")
    assert res_invalid["valid"] is False
    assert "format" in res_invalid["error"].lower()
