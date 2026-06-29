import pytest
from fraudsniffer.ml_detector import DocumentAnomalyDetector, SalaryOutlierScorer

def test_extract_structural_features_empty():
    features = DocumentAnomalyDetector.extract_structural_features("")
    assert features["text_length"] == 0.0
    assert features["entropy"] == 0.0

def test_extract_structural_features():
    text = "Hello World 123 \n Test"
    features = DocumentAnomalyDetector.extract_structural_features(text)
    assert features["text_length"] == 22.0
    assert features["digit_ratio"] > 0.0
    assert features["whitespace_ratio"] > 0.0
    assert features["unique_word_ratio"] == 1.0

def test_compute_anomaly_score_too_few():
    score, devs = DocumentAnomalyDetector.compute_anomaly_score({}, [{}])
    assert score == 0.0
    assert len(devs) == 0

def test_compute_anomaly_score_with_data():
    historical = [
        {"text_length": 100.0, "entropy": 2.0},
        {"text_length": 105.0, "entropy": 2.1},
        {"text_length": 95.0, "entropy": 1.9},
        {"text_length": 102.0, "entropy": 2.0},
        {"text_length": 98.0, "entropy": 2.0},
    ]
    # Inlier
    score, devs = DocumentAnomalyDetector.compute_anomaly_score({"text_length": 100.0, "entropy": 2.0}, historical)
    assert score == 0.0
    
    # Outlier
    score, devs = DocumentAnomalyDetector.compute_anomaly_score({"text_length": 500.0, "entropy": 5.0}, historical)
    assert score > 0.0
    assert len(devs) > 0

def test_salary_outlier_scorer():
    historical = {"acme corp": [50000.0, 52000.0, 48000.0, 51000.0, 49000.0]}
    
    # Missing args
    risk, msg = SalaryOutlierScorer.check_salary("", 0.0, historical)
    assert risk == 0.0
    
    # Not enough history
    risk, msg = SalaryOutlierScorer.check_salary("Unknown", 50000.0, historical)
    assert risk == 0.0
    
    # Inlier
    risk, msg = SalaryOutlierScorer.check_salary("Acme Corp", 50000.0, historical)
    assert risk == 0.0
    
    # High Outlier
    risk, msg = SalaryOutlierScorer.check_salary("Acme Corp", 150000.0, historical)
    assert risk > 0.0
    assert "extreme outlier" in msg

    # Low Outlier
    risk, msg = SalaryOutlierScorer.check_salary("Acme Corp", 10000.0, historical)
    assert risk > 0.0
    assert "significantly lower" in msg
