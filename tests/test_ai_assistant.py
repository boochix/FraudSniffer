import pytest
import os
import json
from pathlib import Path
from fraudsniffer.pipeline import FraudSnifferService
from fraudsniffer.web_app import create_app
from fraudsniffer.ai_assistant import UnderwriterAssistant

def test_storage_ai_chat(tmp_path):
    # Setup service & db
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    doc_id = "test_doc_1"
    
    # Save messages
    service.storage.save_chat_message(doc_id, "user", "Hello assistant")
    service.storage.save_chat_message(doc_id, "assistant", "Hello underwriter")
    
    # Retrieve history
    history = service.storage.get_chat_history(doc_id)
    assert len(history) == 2
    assert history[0]["role"] == "user"
    assert history[0]["message"] == "Hello assistant"
    assert history[1]["role"] == "assistant"
    assert history[1]["message"] == "Hello underwriter"


def test_ai_assistant_fallback():
    assistant = UnderwriterAssistant(ollama_url="http://invalid-localhost:9999", model_name="qwen")
    
    # Check fallback executive summary
    risk_result = {
        "document_type": "PAYSLIP",
        "fraud_score": 0.45,
        "state": "WATCH",
        "risk_decision_reason_codes": ["VPN_DETECTED", "GST_STATE_CODE_INVALID"]
    }
    report = assistant.generate_report("doc_test", risk_result)
    # Verify the report contains structured sections
    assert "Executive Assessment" in report["summary"]
    assert "PAYSLIP" in report["summary"]
    assert "VPN_DETECTED" in report["summary"]
    # Verify draft notes are professional review notes
    assert "doc_test" in report["draft_notes"]
    assert "UNDERWRITER REVIEW NOTE" in report["draft_notes"]
    
    # Check fallback explanation for GST
    explanation = assistant.generate_explanation("GST_STATE_CODE_INVALID", risk_result)
    assert "### Evidence" in explanation
    assert "### Risk" in explanation
    assert "### Recommendation" in explanation
    assert "GSTIN" in explanation
    
    # Check fallback chatbot
    chat_history = [{"role": "user", "message": "Hi"}]
    chat_response = assistant.chat(chat_history, "Explain the GST error please", risk_result)
    assert "GSTIN" in chat_response or "GST" in chat_response


def test_ai_assistant_fallback_report_sections():
    """Verify the fallback report contains all four required sections."""
    assistant = UnderwriterAssistant(ollama_url="http://invalid-localhost:9999")
    
    risk_result = {
        "document_type": "PAYSLIP",
        "fraud_score": 0.82,
        "state": "BLOCK",
        "risk_decision_reason_codes": ["SEAL_MISMATCH", "DUPLICATE_DOCUMENT", "VPN_DETECTED"],
        "classification_confidence": 0.95,
        "feature_values": {
            "employee_name": "Rahul Verma",
            "employer_name": "Skyline Infrastructure",
            "salary_amount": 250000,
            "designation": "Sales Executive",
        },
        "seal_evidence": {
            "seal_phash_distance": 0.312,
            "raw_hamming_distance": 20,
        },
    }
    
    report = assistant.generate_report("doc_block_test", risk_result)
    summary = report["summary"]
    
    # All four sections must be present
    assert "### Executive Assessment" in summary
    assert "### Section A" in summary
    assert "### Section B" in summary
    assert "### Section C" in summary
    assert "### Section D" in summary
    
    # Key values must be present (not hallucinated)
    assert "PAYSLIP" in summary
    assert "95.0%" in summary  # classification confidence
    assert "82.0%" in summary  # fraud score
    assert "BLOCK" in summary
    assert "Rahul Verma" in summary
    assert "Skyline Infrastructure" in summary
    
    # Recommendation should be REJECT for BLOCK state
    assert "REJECT" in summary
    
    # Draft notes should be professional
    notes = report["draft_notes"]
    assert "UNDERWRITER REVIEW NOTE" in notes
    assert "doc_block_test" in notes


def test_ai_assistant_rule_explanations():
    """Verify all rule explanation templates produce valid output."""
    assistant = UnderwriterAssistant(ollama_url="http://invalid-localhost:9999")
    
    rules_to_test = [
        "SEAL_MISMATCH", "DUPLICATE_DOCUMENT", "VPN_DETECTED", "TOR_DETECTED",
        "PAN_NAME_MISMATCH", "COMPANY_NOT_FOUND", "IFSC_INVALID",
        "JOB_SALARY_ANOMALY", "ELA_TAMPERING", "GST_STATE_CODE_INVALID",
    ]
    
    risk_result = {
        "doc_id": "doc_rules_test",
        "feature_values": {"salary_amount": 100000, "designation": "Manager"},
        "seal_evidence": {"seal_phash_distance": 0.25, "raw_hamming_distance": 16},
    }
    
    for rule in rules_to_test:
        explanation = assistant.generate_explanation(rule, risk_result)
        assert "### Evidence" in explanation, f"Missing Evidence section for {rule}"
        assert "### Risk" in explanation, f"Missing Risk section for {rule}"
        assert "### Recommendation" in explanation, f"Missing Recommendation section for {rule}"


def test_ai_assistant_chat_patterns():
    """Verify all conversational QA patterns produce relevant responses."""
    assistant = UnderwriterAssistant(ollama_url="http://invalid-localhost:9999")
    
    risk_result = {
        "doc_id": "doc_chat_test",
        "fraud_score": 0.65,
        "state": "SUSPECT",
        "risk_decision_reason_codes": ["SEAL_MISMATCH", "VPN_DETECTED"],
        "feature_values": {"employee_name": "Test User"},
    }
    
    # Test "why flagged" pattern
    resp = assistant.chat([], "Why was this document flagged?", risk_result)
    assert "SEAL_MISMATCH" in resp or "flagged" in resp.lower()
    
    # Test "evidence" pattern
    resp = assistant.chat([], "What evidence supports this conclusion?", risk_result)
    assert "evidence" in resp.lower() or "analysis" in resp.lower()
    
    # Test "highest risk" pattern
    resp = assistant.chat([], "What is the highest risk finding?", risk_result)
    assert "SEAL_MISMATCH" in resp
    
    # Test "trust" pattern
    resp = assistant.chat([], "Can this document be trusted?", risk_result)
    assert "trust" in resp.lower()
    
    # Test "next steps" pattern
    resp = assistant.chat([], "What should an underwriter do next?", risk_result)
    assert "ESCALATE" in resp
    
    # Test default pattern
    resp = assistant.chat([], "Tell me about quantum computing", risk_result)
    assert "Copilot" in resp or "help" in resp.lower()


def test_ai_assistant_judge_report():
    """Verify the judge demonstration report format."""
    assistant = UnderwriterAssistant(ollama_url="http://invalid-localhost:9999")
    
    risk_result = {
        "document_type": "PAYSLIP",
        "fraud_score": 0.72,
        "state": "SUSPECT",
        "risk_decision_reason_codes": ["SEAL_MISMATCH", "DUPLICATE_DOCUMENT"],
        "classification_confidence": 0.95,
        "feature_values": {
            "employee_name": "Demo User",
            "employer_name": "Demo Corp",
        },
        "seal_evidence": {"seal_phash_distance": 0.3, "raw_hamming_distance": 19},
    }
    
    report = assistant.generate_judge_report("doc_judge_test", risk_result)
    
    assert "FraudSniffer" in report
    assert "SUSPECT" in report
    assert "72.0%" in report
    assert "Demo User" in report
    assert "SEAL_MISMATCH" in report
    assert "WHAT PASSED" in report
    assert "AI RECOMMENDATION" in report
    assert "Dolphin-Llama3 8B" in report


def test_flask_assistant_endpoints(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    app = create_app(service)
    app.testing = True
    client = app.test_client()
    
    doc_id = "doc_api_test"
    
    # Endpoint should return 404 for non-existent document
    res = client.post(f"/api/documents/{doc_id}/assistant/report")
    assert res.status_code == 404
    
    # Create mock document and process it to store a valid risk result
    doc = tmp_path / "doc.txt"
    doc.write_text("Employee Name: Priya\nEmployer Name: Canara\nSalary Amount: 48000\n", encoding="utf-8")
    service.process_file(
        doc,
        {
            "employee_name": "Priya",
            "employer_name": "Canara",
            "salary_amount": 48000
        },
        doc_id=doc_id
    )
    
    # Generate report via endpoint
    res = client.post(f"/api/documents/{doc_id}/assistant/report")
    assert res.status_code == 200
    data = res.get_json()
    assert "summary" in data
    assert "draft_notes" in data
    
    # Chat message post via endpoint
    chat_res = client.post(
        f"/api/documents/{doc_id}/assistant/chat",
        json={"message": "What is the calculated risk?"}
    )
    assert chat_res.status_code == 200
    chat_data = chat_res.get_json()
    assert "message" in chat_data
    assert "fraud risk score" in chat_data["message"].lower() or "risk" in chat_data["message"].lower()
    
    # Explain rule triggers via explain_rule query param
    explain_res = client.post(
        f"/api/documents/{doc_id}/assistant/chat?explain_rule=GST_STATE_CODE_INVALID"
    )
    assert explain_res.status_code == 200
    explain_data = explain_res.get_json()
    assert "GSTIN" in explain_data["message"] or "GST" in explain_data["message"]
    
    # Verify both messages are in chat history
    history_res = client.get(f"/api/documents/{doc_id}/assistant/chat")
    assert history_res.status_code == 200
    history_data = history_res.get_json()
    # We had:
    # 1. User message "What is the calculated risk?"
    # 2. Assistant response
    # 3. User message "Explain finding: GST_STATE_CODE_INVALID"
    # 4. Assistant response
    assert len(history_data) == 4
    assert history_data[0]["role"] == "user"
    assert history_data[2]["message"] == "Explain finding: GST_STATE_CODE_INVALID"
    
    # Test judge demo endpoint
    judge_res = client.post(f"/api/documents/{doc_id}/assistant/judge-report")
    assert judge_res.status_code == 200
    judge_data = judge_res.get_json()
    assert "report" in judge_data
    assert "FraudSniffer" in judge_data["report"]
