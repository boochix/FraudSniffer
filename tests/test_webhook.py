import urllib.error
import urllib.request
from unittest.mock import patch, MagicMock
from fraudsniffer.webhook import post_webhook

def test_post_webhook_skipped():
    result = post_webhook(None, {"test": "data"})
    assert result["status"] == "SKIPPED"

@patch("urllib.request.urlopen")
def test_post_webhook_success(mock_urlopen):
    mock_response = MagicMock()
    mock_response.status = 200
    mock_urlopen.return_value.__enter__.return_value = mock_response

    result = post_webhook("http://example.com/webhook", {"test": "data"})
    assert result["status"] == "SENT"
    assert result["http_status"] == "200"

@patch("urllib.request.urlopen")
def test_post_webhook_failure(mock_urlopen):
    mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
    result = post_webhook("http://example.com/webhook", {"test": "data"})
    assert result["status"] == "FAILED"
    assert "Connection refused" in result["message"]
