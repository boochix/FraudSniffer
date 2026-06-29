from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional


def post_webhook(webhook_url: Optional[str], payload: Dict[str, Any], timeout: float = 4.0) -> Dict[str, Any]:
    if not webhook_url:
        return {"status": "SKIPPED", "message": "No webhook_url configured"}
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {
                "status": "SENT",
                "http_status": str(response.status),
                "message": "Webhook delivered",
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"status": "FAILED", "message": str(exc)}
