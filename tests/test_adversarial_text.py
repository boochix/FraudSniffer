import pytest
from pathlib import Path
from fraudsniffer.adversarial_text import (
    _hidden_unicode_chars,
    normalize_text,
    _jaccard_distance,
    analyze_adversarial_text
)

def test_hidden_unicode_chars():
    # Test zero-width space
    text_with_hidden = "Hello\u200bWorld"
    findings = _hidden_unicode_chars(text_with_hidden)
    assert len(findings) == 1
    assert "U+200B" in findings[0]["codepoint"]

def test_normalize_text():
    text = "Hello\u200bWorld\tTest  Space"
    assert normalize_text(text) == "helloworld test space"

def test_jaccard_distance():
    assert _jaccard_distance([], []) == 0.0
    assert _jaccard_distance(["a"], ["a"]) == 0.0
    assert _jaccard_distance(["a"], ["b"]) == 1.0
    assert _jaccard_distance(["a", "b"], ["b", "c"]) == 0.6666666666666667

def test_analyze_adversarial_text_no_tampering():
    result = analyze_adversarial_text(
        document_path=Path("test.pdf"),
        ocr_text="Hello World",
        pdf_forensics={"raw_text": "Hello World", "visible_text": "Hello World"}
    )
    assert result["hidden_text"]["triggered"] is False
    assert result["raw_ocr_divergence"]["triggered"] is False

def test_analyze_adversarial_text_with_tampering():
    result = analyze_adversarial_text(
        document_path=Path("test.pdf"),
        ocr_text="Hello",
        pdf_forensics={
            "raw_text": "Hello hiddenworld\u200b",
            "visible_text": "Hello",
            "hidden_text_spans": [{"text": "hiddenworld", "x": 0, "y": 0, "w": 0, "h": 0}]
        }
    )
    assert result["hidden_text"]["triggered"] is True
    assert result["hidden_text"]["hidden_span_count"] == 1
    assert result["raw_ocr_divergence"]["triggered"] is True
