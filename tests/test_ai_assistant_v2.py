import pytest
from fraudsniffer.ai_assistant import UnderwriterAssistant

def test_ai_assistant_v2_report_structure():
    assistant = UnderwriterAssistant(ollama_url="http://invalid-localhost:9999")
    
    risk_result = {
        "document_type": "PAYSLIP",
        "fraud_score": 0.82,
        "state": "BLOCK",
        "risk_decision_reason_codes": ["SEAL_MISMATCH", "DEVICE_CLONE"],
        "classification_confidence": 0.95
    }
    
    report = assistant.generate_report("doc_test_123", risk_result)
    summary = report["summary"]
    
    assert "### Executive Assessment" in summary
    assert "### Section B — Primary Findings" in summary
    assert "### Section D — Recommended Action" in summary
    assert "PAYSLIP" in summary
    assert "95.0%" in summary
    assert "82.0%" in summary
    assert "BLOCK" in summary
    assert "Seal Verification Failure" in summary
    assert "Behavioral & Network Anomaly" in summary


def test_ai_assistant_v2_explanation_structure_and_metrics():
    from unittest.mock import MagicMock, patch

    class MockRow(dict):
        def __getitem__(self, item):
            if isinstance(item, int):
                return list(self.values())[item]
            return super().__getitem__(item)

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    
    last_query = []
    def mock_execute(sql, *args, **kwargs):
        last_query.append(sql)
    mock_cursor.execute.side_effect = mock_execute

    def mock_fetchone():
        if not last_query:
            return None
        sql = last_query[-1]
        if "file_hash_sha3 FROM documents" in sql:
            return MockRow({"file_hash_sha3": "hash123"})
        if "doc_id, created_at FROM documents" in sql:
            return MockRow({"doc_id": "doc_91f73a", "created_at": 1770000000})
        return None
    mock_cursor.fetchone.side_effect = mock_fetchone
    
    mock_conn.cursor.return_value = mock_cursor

    with patch("fraudsniffer.ai_assistant.get_db_connection", return_value=mock_conn):
        assistant = UnderwriterAssistant(ollama_url="http://invalid-localhost:9999")
        
        risk_result = {
            "doc_id": "doc_test_99",
            "feature_values": {
                "designation": "Junior Sales Executive",
                "salary_amount": 250000.0,
                "parse_coverage_score": 0.15
            },
            "seal_evidence": {
                "seal_phash_distance": 0.531,
                "raw_hamming_distance": 34
            }
        }
        
        # 1. Test SEAL_MISMATCH explanation
        seal_explain = assistant.generate_explanation("SEAL_MISMATCH", risk_result)
        assert "### Evidence" in seal_explain
        assert "### Risk" in seal_explain
        assert "### Recommendation" in seal_explain
        assert "34" in seal_explain
        assert "0.531" in seal_explain
        assert "forgery" in seal_explain.lower()
        
        # 2. Test DUPLICATE_DOCUMENT explanation (fallback defaults)
        dup_explain = assistant.generate_explanation("DUPLICATE_DOCUMENT", risk_result)
        assert "### Evidence" in dup_explain
        assert "doc_91f73a" in dup_explain
        assert "Direct duplicates are flagged separately" in dup_explain
        
        # 3. Test JOB_SALARY_ANOMALY explanation
        job_explain = assistant.generate_explanation("JOB_SALARY_ANOMALY", risk_result)
        assert "Junior Sales Executive" in job_explain
        assert "₹250,000.00" in job_explain
        
        # 4. Test PARSE_COVERAGE_LOW explanation
        cov_explain = assistant.generate_explanation("PARSE_COVERAGE_LOW", risk_result)
        assert "15.0%" in cov_explain
