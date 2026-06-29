"""Behavioral Analytics Detector for FraudSniffer.

Performs device-level, network-level, and submission-velocity checks
on client telemetry data to detect bot farms, device emulators,
impossible travel, scripted submissions, and repeat fraud patterns.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import ReasonCode, TelemetryData
from .storage import FraudStorage


@dataclass
class BehavioralAlert:
    """A single behavioral risk finding."""
    rule: str            # e.g. "DEVICE_CLONE"
    severity: str        # "HIGH", "MEDIUM", "LOW"
    score: float         # 0.0 – 1.0 confidence contribution
    detail: str          # Human-readable explanation
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "score": round(self.score, 4),
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class BehavioralResult:
    """Aggregated result of all behavioral checks."""
    alerts: List[BehavioralAlert] = field(default_factory=list)
    total_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alerts": [a.to_dict() for a in self.alerts],
            "total_score": round(self.total_score, 4),
            "alert_count": len(self.alerts),
        }


# ── Constants ──────────────────────────────────────────────────
DEVICE_CLONE_THRESHOLD = 3          # Flag if >3 docs from same fingerprint in 24h
SCRIPTED_SUBMISSION_MS = 1500       # Flag if form submitted in <1.5 seconds
SCRIPTED_KEYSTROKE_MS = 200         # Flag if total keystrokes took <200ms (copy-paste)
IMPOSSIBLE_TRAVEL_KMH = 1000       # Commercial airliner cruising speed
REPEAT_PATTERN_THRESHOLD = 5       # Flag if >=5 identical employer/salary/device combos
EARTH_RADIUS_KM = 6371.0


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points on Earth using the Haversine formula."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


# ── Stub GeoIP Lookup ──────────────────────────────────────────
# In production, replace with MaxMind GeoLite2 or ip-api.com
_STUB_GEO_DB: Dict[str, Dict[str, float]] = {
    "127.0.0.1": {"lat": 19.076, "lon": 72.8777, "city": "Mumbai"},
    "192.168.1.1": {"lat": 19.076, "lon": 72.8777, "city": "Mumbai"},
    "10.0.0.1": {"lat": 28.6139, "lon": 77.2090, "city": "Delhi"},
}


def _geolocate_ip(ip: str) -> Optional[Dict[str, Any]]:
    """Stub geolocation — returns known locations or None."""
    return _STUB_GEO_DB.get(ip)


# ── Known VPN/Tor Exit Stubs ──────────────────────────────────
_KNOWN_VPN_RANGES = {"10.8.", "172.16.", "100.64."}
_KNOWN_TOR_EXITS = {"185.220.101.", "185.220.102.", "23.129.64."}


def _check_vpn_tor(ip: str) -> Dict[str, bool]:
    """Stub VPN/Tor/Proxy detection using prefix matching."""
    return {
        "vpn": any(ip.startswith(prefix) for prefix in _KNOWN_VPN_RANGES),
        "tor": any(ip.startswith(prefix) for prefix in _KNOWN_TOR_EXITS),
        "proxy": False,  # Would require header inspection in production
    }


class BehavioralDetector:
    """Runs all behavioral analysis checks against a telemetry payload."""

    def __init__(self, storage: FraudStorage):
        self.storage = storage

    def evaluate(
        self,
        doc_id: str,
        telemetry: TelemetryData,
        employer_name: Optional[str] = None,
        salary_amount: Optional[float] = None,
        seal_phash: Optional[str] = None,
    ) -> BehavioralResult:
        """Run the complete behavioral analysis suite and return aggregated results."""
        result = BehavioralResult()

        # 1. Device Cloning Check
        clone_alert = self._check_device_clone(telemetry)
        if clone_alert:
            result.alerts.append(clone_alert)

        # 2. Scripted Submission Check
        script_alert = self._check_scripted_submission(telemetry)
        if script_alert:
            result.alerts.append(script_alert)

        # 3. VPN / Tor Detection
        vpn_alert = self._check_vpn_tor(telemetry)
        if vpn_alert:
            result.alerts.append(vpn_alert)

        # 4. Impossible Travel Check
        travel_alert = self._check_impossible_travel(telemetry)
        if travel_alert:
            result.alerts.append(travel_alert)

        # 5. Repeat Fraud Fingerprinting (Cluster Detection)
        cluster_alert = self._check_repeat_pattern(
            telemetry, employer_name, salary_amount
        )
        if cluster_alert:
            result.alerts.append(cluster_alert)

        # Calculate total behavioral score
        result.total_score = min(
            sum(alert.score for alert in result.alerts), 1.0
        )
        return result

    # ── Individual Check Implementations ──────────────────────

    def _check_device_clone(self, telemetry: TelemetryData) -> Optional[BehavioralAlert]:
        """Flag if the same canvas fingerprint has submitted >THRESHOLD docs in 24h."""
        fp = telemetry.canvas_fingerprint
        if not fp:
            return None

        recent = self.storage.get_recent_telemetry_by_fingerprint(fp, hours=24)
        count = len(recent)

        if count > DEVICE_CLONE_THRESHOLD:
            return BehavioralAlert(
                rule=ReasonCode.DEVICE_CLONE.value,
                severity="HIGH",
                score=min(0.30, 0.10 + (count - DEVICE_CLONE_THRESHOLD) * 0.05),
                detail=(
                    f"Device fingerprint has submitted {count} documents in the last 24 hours "
                    f"(threshold: {DEVICE_CLONE_THRESHOLD}). Suspected device emulator or bot farm."
                ),
                evidence={
                    "canvas_fingerprint": fp,
                    "submissions_24h": count,
                    "threshold": DEVICE_CLONE_THRESHOLD,
                    "associated_doc_ids": [r["doc_id"] for r in recent[:10]],
                },
            )
        return None

    def _check_scripted_submission(self, telemetry: TelemetryData) -> Optional[BehavioralAlert]:
        """Flag if form was completed and submitted inhumanly fast."""
        alerts_detail = []
        score = 0.0

        if 0 < telemetry.submission_duration_ms < SCRIPTED_SUBMISSION_MS:
            alerts_detail.append(
                f"Submission completed in {telemetry.submission_duration_ms}ms "
                f"(threshold: {SCRIPTED_SUBMISSION_MS}ms)"
            )
            score += 0.20

        if 0 < telemetry.keystroke_duration_ms < SCRIPTED_KEYSTROKE_MS:
            alerts_detail.append(
                f"Total keystroke duration {telemetry.keystroke_duration_ms}ms "
                f"(threshold: {SCRIPTED_KEYSTROKE_MS}ms) — likely copy-paste or autofill"
            )
            score += 0.10

        if alerts_detail:
            return BehavioralAlert(
                rule=ReasonCode.SCRIPTED_SUBMISSION.value,
                severity="MEDIUM" if score < 0.25 else "HIGH",
                score=min(score, 0.30),
                detail=" | ".join(alerts_detail),
                evidence={
                    "submission_duration_ms": telemetry.submission_duration_ms,
                    "keystroke_duration_ms": telemetry.keystroke_duration_ms,
                    "submission_threshold_ms": SCRIPTED_SUBMISSION_MS,
                    "keystroke_threshold_ms": SCRIPTED_KEYSTROKE_MS,
                },
            )
        return None

    def _check_vpn_tor(self, telemetry: TelemetryData) -> Optional[BehavioralAlert]:
        """Flag if the client IP belongs to a known VPN, Tor exit, or proxy network."""
        ip = telemetry.ip_address
        if not ip:
            return None

        network_flags = _check_vpn_tor(ip)
        detected = [k for k, v in network_flags.items() if v]

        if detected:
            return BehavioralAlert(
                rule=ReasonCode.VPN_DETECTED.value,
                severity="MEDIUM",
                score=0.10,
                detail=f"Client IP {ip} detected as: {', '.join(detected).upper()}. Source identity may be obfuscated.",
                evidence={
                    "ip_address": ip,
                    "vpn": network_flags["vpn"],
                    "tor": network_flags["tor"],
                    "proxy": network_flags["proxy"],
                },
            )
        return None

    def _check_impossible_travel(self, telemetry: TelemetryData) -> Optional[BehavioralAlert]:
        """Check if the user's IP location is physically impossible given their last submission."""
        ip = telemetry.ip_address
        if not ip:
            return None

        # Look up current geo
        current_geo = _geolocate_ip(ip)
        if not current_geo:
            return None

        # Find the most recent submission from any IP by this device fingerprint
        recent = self.storage.get_recent_telemetry_by_fingerprint(
            telemetry.canvas_fingerprint, hours=24
        )
        if len(recent) < 2:
            return None

        # Compare against the second-most-recent entry (index 0 is current)
        for prev in recent[1:]:
            prev_ip = prev.get("ip_address", "")
            if prev_ip == ip:
                continue  # Same IP, no travel

            prev_geo = _geolocate_ip(prev_ip)
            if not prev_geo:
                continue

            distance_km = _haversine_km(
                current_geo["lat"], current_geo["lon"],
                prev_geo["lat"], prev_geo["lon"],
            )
            time_diff_h = max(
                (time.time() - prev["created_at"]) / 3600.0, 0.001
            )
            velocity_kmh = distance_km / time_diff_h

            if velocity_kmh > IMPOSSIBLE_TRAVEL_KMH and distance_km > 100:
                return BehavioralAlert(
                    rule=ReasonCode.IMPOSSIBLE_TRAVEL.value,
                    severity="HIGH",
                    score=min(0.25, 0.15 + (velocity_kmh / 10000)),
                    detail=(
                        f"Impossible travel detected: {distance_km:.0f} km in "
                        f"{time_diff_h * 60:.1f} minutes ({velocity_kmh:.0f} km/h). "
                        f"Max plausible: {IMPOSSIBLE_TRAVEL_KMH} km/h."
                    ),
                    evidence={
                        "current_ip": ip,
                        "previous_ip": prev_ip,
                        "distance_km": round(distance_km, 1),
                        "time_diff_minutes": round(time_diff_h * 60, 1),
                        "velocity_kmh": round(velocity_kmh, 0),
                        "threshold_kmh": IMPOSSIBLE_TRAVEL_KMH,
                    },
                )
        return None

    def _check_repeat_pattern(
        self,
        telemetry: TelemetryData,
        employer_name: Optional[str],
        salary_amount: Optional[float],
    ) -> Optional[BehavioralAlert]:
        """Detect repeat fraud fingerprinting — same employer, salary, and device across many submissions."""
        fp = telemetry.canvas_fingerprint
        if not fp or not employer_name or salary_amount is None:
            return None

        matches = self.storage.get_repeat_pattern_matches(
            employer_name, salary_amount, fp
        )

        if len(matches) >= REPEAT_PATTERN_THRESHOLD:
            return BehavioralAlert(
                rule=ReasonCode.KNOWN_DEVICE_CLUSTER.value,
                severity="HIGH",
                score=min(0.35, 0.15 + len(matches) * 0.04),
                detail=(
                    f"Repeat fraud pattern detected: {len(matches)} historical submissions "
                    f"share identical employer ('{employer_name}'), salary (₹{salary_amount:,.0f}), "
                    f"and device fingerprint. Suspected collusive fraud ring."
                ),
                evidence={
                    "match_count": len(matches),
                    "threshold": REPEAT_PATTERN_THRESHOLD,
                    "employer": employer_name,
                    "salary": salary_amount,
                    "canvas_fingerprint": fp,
                    "matching_doc_ids": [m["doc_id"] for m in matches[:10]],
                },
            )
        return None
