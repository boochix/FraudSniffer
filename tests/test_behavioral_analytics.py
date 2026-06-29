from __future__ import annotations

import json
from pathlib import Path

from fraudsniffer.behavioral_detector import BehavioralDetector
from fraudsniffer.models import ReasonCode, PipelineState, TelemetryData
from fraudsniffer.storage import FraudStorage


def _storage(tmp_path: Path) -> FraudStorage:
    return FraudStorage(tmp_path / "fraud.db")


def _touch_doc(path: Path, text: str = "doc") -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_device_clone_threshold(tmp_path):
    storage = _storage(tmp_path)
    detector = BehavioralDetector(storage)
    for index in range(4):
        storage.save_telemetry(
            f"doc_clone_{index}",
            TelemetryData(canvas_fingerprint="fp-clone", ip_address="127.0.0.1"),
        )

    result = detector.evaluate("doc_clone_current", TelemetryData(canvas_fingerprint="fp-clone"))

    assert any(alert.rule == ReasonCode.DEVICE_CLONE.value for alert in result.alerts)


def test_scripted_submission_timing(tmp_path):
    detector = BehavioralDetector(_storage(tmp_path))

    result = detector.evaluate(
        "doc_script",
        TelemetryData(
            canvas_fingerprint="fp-script",
            submission_duration_ms=500,
            keystroke_duration_ms=100,
        ),
    )

    assert any(alert.rule == ReasonCode.SCRIPTED_SUBMISSION.value for alert in result.alerts)


def test_vpn_tor_prefix_detection(tmp_path):
    detector = BehavioralDetector(_storage(tmp_path))

    result = detector.evaluate(
        "doc_vpn",
        TelemetryData(canvas_fingerprint="fp-vpn", ip_address="10.8.0.5"),
    )

    assert any(alert.rule == ReasonCode.VPN_DETECTED.value for alert in result.alerts)


def test_impossible_travel_with_stub_geoip(tmp_path):
    storage = _storage(tmp_path)
    detector = BehavioralDetector(storage)
    fp = "fp-travel"
    storage.save_telemetry("doc_prev", TelemetryData(canvas_fingerprint=fp, ip_address="10.0.0.1"))
    current = TelemetryData(canvas_fingerprint=fp, ip_address="127.0.0.1")
    storage.save_telemetry("doc_current", current)

    result = detector.evaluate("doc_current", current)

    assert any(alert.rule == ReasonCode.IMPOSSIBLE_TRAVEL.value for alert in result.alerts)


def test_repeat_pattern_cluster_detection(tmp_path):
    storage = _storage(tmp_path)
    detector = BehavioralDetector(storage)
    fp = "fp-cluster"
    source = _touch_doc(tmp_path / "source.txt")

    for index in range(5):
        doc_id = f"doc_cluster_{index}"
        storage.create_document(doc_id, source, f"hash-{index}", {})
        storage.save_telemetry(doc_id, TelemetryData(canvas_fingerprint=fp, ip_address="127.0.0.1"))
        risk_json = {
            "feature_values": {
                "employer_name": "Canara Tech",
                "salary_amount": 48000,
            }
        }
        with storage._connect() as conn:
            conn.execute(
                """
                UPDATE documents
                SET risk_json = ?, pipeline_state = ?
                WHERE doc_id = ?
                """,
                (json.dumps(risk_json), PipelineState.FINALIZED.value, doc_id),
            )

    result = detector.evaluate(
        "doc_cluster_current",
        TelemetryData(canvas_fingerprint=fp, ip_address="127.0.0.1"),
        employer_name="Canara Tech",
        salary_amount=48000,
    )

    assert any(alert.rule == ReasonCode.KNOWN_DEVICE_CLUSTER.value for alert in result.alerts)
