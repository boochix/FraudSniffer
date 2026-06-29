from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


CHAIN_VERSION = 2
SIGNATURE_SCHEME = "hmac-sha3-audit"
SIGNER_ID = "audit-key-001"
ZERO_HASH = "0" * 64
logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha3_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


class HMACAuditSigner:
    """Fast local v2 audit signer with deterministic SHA3/HMAC verification.

    The public interface intentionally names the local audit scheme used by the
    dashboard. It keeps FraudSniffer self-contained and, unlike the v1 mock,
    guarantees sign/verify round trips and tamper rejection.
    """

    @classmethod
    def generate_keypair(cls, signer_id: str = SIGNER_ID) -> tuple[bytes, bytes]:
        secret = secrets.token_bytes(32)
        public_key = {
            "chain_version": CHAIN_VERSION,
            "signature_scheme": SIGNATURE_SCHEME,
            "signer_id": signer_id,
            "key_hash": _sha3_hex(secret),
        }
        secret_key = {
            "chain_version": CHAIN_VERSION,
            "signature_scheme": SIGNATURE_SCHEME,
            "signer_id": signer_id,
            "secret_b64": _b64(secret),
        }
        return (
            _canonical_json(public_key).encode("utf-8"),
            _canonical_json(secret_key).encode("utf-8"),
        )

    @classmethod
    def sign(cls, payload_hash: bytes, secret_key: bytes) -> bytes:
        key = json.loads(secret_key.decode("utf-8"))
        secret = _unb64(key["secret_b64"])
        digest = hmac.new(
            secret,
            SIGNATURE_SCHEME.encode("ascii") + b":" + payload_hash,
            hashlib.sha3_256,
        ).digest()
        signature = {
            "chain_version": CHAIN_VERSION,
            "signature_scheme": SIGNATURE_SCHEME,
            "signer_id": key.get("signer_id", SIGNER_ID),
            "digest_b64": _b64(digest),
        }
        return _canonical_json(signature).encode("utf-8")

    @classmethod
    def verify(cls, payload_hash: bytes, signature: bytes, public_key: bytes, secret_key: bytes) -> bool:
        try:
            pk = json.loads(public_key.decode("utf-8"))
            sk = json.loads(secret_key.decode("utf-8"))
            sig = json.loads(signature.decode("utf-8"))
            if pk.get("signature_scheme") != SIGNATURE_SCHEME:
                return False
            if sk.get("signature_scheme") != SIGNATURE_SCHEME:
                return False
            if sig.get("signature_scheme") != SIGNATURE_SCHEME:
                return False
            if pk.get("signer_id") != sk.get("signer_id") or pk.get("signer_id") != sig.get("signer_id"):
                return False
            secret = _unb64(sk["secret_b64"])
            if pk.get("key_hash") != _sha3_hex(secret):
                return False
            expected = hmac.new(
                secret,
                SIGNATURE_SCHEME.encode("ascii") + b":" + payload_hash,
                hashlib.sha3_256,
            ).digest()
            actual = _unb64(sig["digest_b64"])
            return hmac.compare_digest(expected, actual)
        except Exception:
            return False


@dataclass
class VerificationResult:
    ok: bool
    message: str
    failed_block: Optional[int]
    failure_type: Optional[str]
    blocks_verified: int
    total_blocks: int
    signatures_valid: int
    total_signatures: int
    verification_percentage: float
    verification_time_ms: float
    verification_failed_at: Optional[str] = None
    signature_scheme: str = SIGNATURE_SCHEME
    chain_version: int = CHAIN_VERSION
    signer_id: str = SIGNER_ID

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "message": self.message,
            "failed_block": self.failed_block,
            "failure_type": self.failure_type,
            "blocks_verified": self.blocks_verified,
            "total_blocks": self.total_blocks,
            "signatures_valid": self.signatures_valid,
            "total_signatures": self.total_signatures,
            "verification_percentage": round(self.verification_percentage, 1),
            "verification_time_ms": round(self.verification_time_ms, 3),
            "verification_failed_at": self.verification_failed_at,
            "signature_scheme": self.signature_scheme,
            "chain_version": self.chain_version,
            "signer_id": self.signer_id,
        }


class PQCAuditEntry:
    """A single entry in the Post-Quantum Cryptographic audit log chain."""

    def __init__(
        self,
        index: int,
        timestamp: float,
        doc_id: str,
        event_type: str,
        details: Dict[str, Any],
        previous_hash: str,
        chain_version: int = CHAIN_VERSION,
        signature_scheme: str = SIGNATURE_SCHEME,
        signer_id: str = SIGNER_ID,
        signed_at: Optional[str] = None,
        payload_hash: Optional[str] = None,
        signature: Optional[str] = None,
        public_key: Optional[str] = None,
    ):
        self.index = index
        self.timestamp = timestamp
        self.doc_id = doc_id
        self.event_type = event_type
        self.details = details
        self.previous_hash = previous_hash
        self.chain_version = chain_version
        self.signature_scheme = signature_scheme
        self.signer_id = signer_id
        self.signed_at = signed_at
        self.payload_hash = payload_hash
        self.signature = signature
        self.public_key = public_key

    def signing_payload(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "doc_id": self.doc_id,
            "event_type": self.event_type,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "chain_version": self.chain_version,
            "signature_scheme": self.signature_scheme,
            "signer_id": self.signer_id,
        }

    def compute_hash(self) -> str:
        """Compute the SHA3-256 hash of the immutable signed payload."""
        return _sha3_hex(_canonical_json(self.signing_payload()).encode("utf-8"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "doc_id": self.doc_id,
            "event_type": self.event_type,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "chain_version": self.chain_version,
            "signature_scheme": self.signature_scheme,
            "signer_id": self.signer_id,
            "signed_at": self.signed_at,
            "payload_hash": self.payload_hash,
            "signature": self.signature,
            "public_key": self.public_key,
        }


class PQCAuditTrail:
    """A tamper-evident cryptographic ledger for document events."""

    def __init__(self, audit_dir: Path | str):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.chain_file = self.audit_dir / "audit_chain.json"
        self.keys_file = self.audit_dir / "audit_keys.json"
        self.legacy_recovered = False
        self.pk: Optional[bytes] = None
        self.sk: Optional[bytes] = None

        self._backup_legacy_files_if_needed()
        self.pk, self.sk = self._load_or_generate_keys()
        self._ensure_chain()

    def _backup_path(self, path: Path) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return path.with_name(f"{path.stem}.legacy.{stamp}{path.suffix}.bak")

    def _backup_legacy_files_if_needed(self, force: bool = False) -> None:
        if not force and not self._has_legacy_chain() and not self._has_legacy_keys():
            return
        for path in (self.chain_file, self.keys_file):
            if path.exists():
                backup_path = self._backup_path(path)
                shutil.move(str(path), str(backup_path))
                logger.warning("Backed up incompatible PQC audit file %s to %s", path, backup_path)
        self.legacy_recovered = True

    def _has_legacy_chain(self) -> bool:
        if not self.chain_file.exists():
            return False
        try:
            raw = json.loads(self.chain_file.read_text(encoding="utf-8"))
            if not isinstance(raw, list) or not raw:
                return False
            genesis = raw[0]
            details = genesis.get("details") or {}
            if details.get("chain_version") != CHAIN_VERSION:
                return True
            return any(
                entry.get("index", 0) > 0
                and entry.get("signature_scheme") != SIGNATURE_SCHEME
                for entry in raw
            )
        except Exception:
            return False

    def _has_legacy_keys(self) -> bool:
        if not self.keys_file.exists():
            return False
        try:
            keys = json.loads(self.keys_file.read_text(encoding="utf-8"))
            return not self._valid_key_payload(keys)
        except Exception:
            return True

    def _valid_key_payload(self, keys: Dict[str, Any]) -> bool:
        if keys.get("chain_version") != CHAIN_VERSION:
            return False
        if keys.get("signature_scheme") != SIGNATURE_SCHEME:
            return False
        if keys.get("signer_id", SIGNER_ID) != SIGNER_ID:
            return False
        try:
            public_key = _unb64(str(keys["public_key"]))
            secret_key = _unb64(str(keys["secret_key"]))
            public_payload = json.loads(public_key.decode("utf-8"))
            secret_payload = json.loads(secret_key.decode("utf-8"))
            if public_payload.get("chain_version") != CHAIN_VERSION:
                return False
            if secret_payload.get("chain_version") != CHAIN_VERSION:
                return False
            if public_payload.get("signature_scheme") != SIGNATURE_SCHEME:
                return False
            if secret_payload.get("signature_scheme") != SIGNATURE_SCHEME:
                return False
            secret = _unb64(str(secret_payload["secret_b64"]))
            return public_payload.get("key_hash") == _sha3_hex(secret)
        except Exception:
            return False

    def _write_new_keys(self) -> tuple[bytes, bytes]:
        pk, sk = HMACAuditSigner.generate_keypair(SIGNER_ID)
        self.keys_file.write_text(
            json.dumps(
                {
                    "chain_version": CHAIN_VERSION,
                    "signature_scheme": SIGNATURE_SCHEME,
                    "signer_id": SIGNER_ID,
                    "created_at": _utc_now_iso(),
                    "public_key": _b64(pk),
                    "secret_key": _b64(sk),
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return pk, sk

    def _load_or_generate_keys(self) -> tuple[Optional[bytes], Optional[bytes]]:
        if self.keys_file.exists():
            try:
                keys = json.loads(self.keys_file.read_text(encoding="utf-8"))
                if not self._valid_key_payload(keys):
                    logger.warning("PQC audit key file is invalid or incompatible; starting a fresh audit chain.")
                    self._backup_legacy_files_if_needed(force=True)
                    return self._write_new_keys()
                return _unb64(keys["public_key"]), _unb64(keys["secret_key"])
            except Exception as exc:
                logger.warning("PQC audit key file could not be parsed (%s); starting a fresh audit chain.", exc)
                self._backup_legacy_files_if_needed(force=True)
                return self._write_new_keys()

        if self.chain_file.exists():
            logger.warning("PQC audit chain exists without local signing keys; starting a fresh audit chain.")
            self._backup_legacy_files_if_needed(force=True)

        return self._write_new_keys()

    def _ensure_chain(self) -> None:
        if not self.chain_file.exists():
            self._save_chain([self._genesis_entry()])

    def _genesis_entry(self) -> PQCAuditEntry:
        return PQCAuditEntry(
            index=0,
            timestamp=time.time(),
            doc_id="genesis",
            event_type="GENESIS",
            details={
                "event": "GENESIS",
                "message": "FraudSniffer PQC Audit Chain Initialized",
                "created_by": "FraudSniffer",
                "chain_version": CHAIN_VERSION,
                "signature_scheme": SIGNATURE_SCHEME,
                "signer_id": SIGNER_ID,
            },
            previous_hash=ZERO_HASH,
            chain_version=CHAIN_VERSION,
            signature_scheme=SIGNATURE_SCHEME,
            signer_id=SIGNER_ID,
        )

    def _load_chain(self) -> List[PQCAuditEntry]:
        if not self.chain_file.exists():
            self._ensure_chain()
        try:
            data = json.loads(self.chain_file.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                return []
            return [
                PQCAuditEntry(
                    index=int(e["index"]),
                    timestamp=float(e["timestamp"]),
                    doc_id=str(e["doc_id"]),
                    event_type=str(e["event_type"]),
                    details=dict(e.get("details") or {}),
                    previous_hash=str(e["previous_hash"]),
                    chain_version=int(e.get("chain_version", 1)),
                    signature_scheme=str(e.get("signature_scheme", "")),
                    signer_id=str(e.get("signer_id", "")),
                    signed_at=e.get("signed_at"),
                    payload_hash=e.get("payload_hash"),
                    signature=e.get("signature"),
                    public_key=e.get("public_key"),
                )
                for e in data
            ]
        except Exception:
            return []

    def _save_chain(self, chain: List[PQCAuditEntry]) -> None:
        self.chain_file.write_text(
            json.dumps([e.to_dict() for e in chain], indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def record_event(self, doc_id: str, event_type: str, details: Dict[str, Any]) -> PQCAuditEntry:
        """Append an event to the ledger and sign it."""
        if not self.pk or not self.sk:
            raise RuntimeError("PQC audit signing keys are missing or invalid")

        chain = self._load_chain()
        if not chain:
            raise RuntimeError("Audit chain is uninitialized or corrupted")

        previous_hash = chain[-1].compute_hash()
        new_entry = PQCAuditEntry(
            index=len(chain),
            timestamp=time.time(),
            doc_id=doc_id,
            event_type=event_type,
            details=details,
            previous_hash=previous_hash,
            chain_version=CHAIN_VERSION,
            signature_scheme=SIGNATURE_SCHEME,
            signer_id=SIGNER_ID,
            signed_at=_utc_now_iso(),
            public_key=_b64(self.pk),
        )
        new_entry.payload_hash = new_entry.compute_hash()
        new_entry.signature = _b64(HMACAuditSigner.sign(new_entry.payload_hash.encode("ascii"), self.sk))

        chain.append(new_entry)
        self._save_chain(chain)
        return new_entry

    def verify_chain_integrity(self) -> Dict[str, Any]:
        """Validate hash linkage and signatures, returning a structured result."""
        started = time.perf_counter()
        chain = self._load_chain()
        total_blocks = len(chain)
        total_signatures = max(total_blocks - 1, 0)

        def result(
            ok: bool,
            message: str,
            failed_block: Optional[int],
            failure_type: Optional[str],
            blocks_verified: int,
            signatures_valid: int,
        ) -> Dict[str, Any]:
            elapsed = (time.perf_counter() - started) * 1000
            pct = (blocks_verified / total_blocks * 100.0) if total_blocks else 0.0
            return VerificationResult(
                ok=ok,
                message=message,
                failed_block=failed_block,
                failure_type=failure_type,
                blocks_verified=blocks_verified,
                total_blocks=total_blocks,
                signatures_valid=signatures_valid,
                total_signatures=total_signatures,
                verification_percentage=pct,
                verification_time_ms=elapsed,
                verification_failed_at=None if ok else _utc_now_iso(),
            ).to_dict()

        if not chain:
            return result(False, "Empty or missing audit trail chain.", None, "corrupted_entry", 0, 0)

        genesis = chain[0]
        if genesis.event_type != "GENESIS" or genesis.previous_hash != ZERO_HASH:
            return result(False, "Genesis block is corrupted.", 0, "corrupted_entry", 0, 0)
        if genesis.chain_version != CHAIN_VERSION or genesis.details.get("chain_version") != CHAIN_VERSION:
            return result(False, "Unsupported genesis chain version.", 0, "unsupported_scheme", 0, 0)
        if genesis.signature_scheme != SIGNATURE_SCHEME:
            return result(False, "Unsupported genesis signature scheme.", 0, "unsupported_scheme", 0, 0)

        blocks_verified = 1
        signatures_valid = 0
        for i in range(1, total_blocks):
            current = chain[i]
            previous = chain[i - 1]

            if current.chain_version != CHAIN_VERSION:
                return result(False, f"Unsupported chain version at block {i}.", i, "unsupported_scheme", blocks_verified, signatures_valid)
            if current.signature_scheme != SIGNATURE_SCHEME:
                return result(False, f"Unsupported signature scheme at block {i}.", i, "unsupported_scheme", blocks_verified, signatures_valid)
            computed_previous_hash = previous.compute_hash()
            if current.previous_hash != computed_previous_hash:
                return result(
                    False,
                    f"Hash linkage broken at block {i}: expected previous_hash {computed_previous_hash}, found {current.previous_hash}.",
                    i,
                    "hash_link",
                    blocks_verified,
                    signatures_valid,
                )
            if not current.signature or not current.public_key or not current.signer_id:
                return result(False, f"Block {i} is missing signature, public key, or signer identity.", i, "missing_key", blocks_verified, signatures_valid)
            if current.signer_id != SIGNER_ID:
                return result(False, f"No trusted key registered for signer {current.signer_id} at block {i}.", i, "missing_key", blocks_verified, signatures_valid)
            computed_payload_hash = current.compute_hash()
            if current.payload_hash != computed_payload_hash:
                return result(False, f"Payload hash mismatch at block {i}.", i, "corrupted_entry", blocks_verified, signatures_valid)
            if not self.sk:
                return result(False, "PQC secret key is unavailable for local audit verification.", i, "missing_key", blocks_verified, signatures_valid)
            try:
                pk_bytes = _unb64(current.public_key)
                sig_bytes = _unb64(current.signature)
            except Exception:
                return result(False, f"Block {i} contains malformed signature material.", i, "corrupted_entry", blocks_verified, signatures_valid)
            if not HMACAuditSigner.verify(current.payload_hash.encode("ascii"), sig_bytes, pk_bytes, self.sk):
                return result(False, f"Signature verification failed at block {i}.", i, "signature", blocks_verified, signatures_valid)

            blocks_verified += 1
            signatures_valid += 1

        return result(True, f"Audit trail verified successfully. Total entries: {total_blocks}.", None, None, total_blocks, total_signatures)

    def get_timeline_for_document(self, doc_id: str) -> List[Dict[str, Any]]:
        """Return timeline events related to a specific document."""
        chain = self._load_chain()
        verification = self.verify_chain_integrity()
        failed_block = verification.get("failed_block")
        ok = bool(verification.get("ok"))
        events = []
        for entry in chain:
            if entry.doc_id != doc_id:
                continue
            verified = ok or failed_block is None or entry.index < failed_block
            if entry.index == failed_block:
                verified = False
            events.append(
                {
                    "index": entry.index,
                    "timestamp": entry.timestamp,
                    "event_type": entry.event_type,
                    "details": entry.details,
                    "signed_at": entry.signed_at,
                    "payload_hash": entry.payload_hash,
                    "signature_scheme": entry.signature_scheme,
                    "signer_id": entry.signer_id,
                    "signature_verified": verified,
                }
            )
        return sorted(events, key=lambda x: x["timestamp"])

    def run_startup_self_test(self) -> Dict[str, Any]:
        """Run key-load, sign/verify, and ledger verification diagnostics."""
        keys_loaded = bool(self.pk and self.sk)
        signature_roundtrip = False
        if keys_loaded and self.pk and self.sk:
            probe_hash = _sha3_hex(b"fraudsniffer-pqc-startup-self-test").encode("ascii")
            signature = HMACAuditSigner.sign(probe_hash, self.sk)
            signature_roundtrip = HMACAuditSigner.verify(probe_hash, signature, self.pk, self.sk)
        verification = self.verify_chain_integrity()
        return {
            "keys_loaded": keys_loaded,
            "signature_roundtrip_ok": signature_roundtrip,
            "ledger_verified": bool(verification.get("ok")),
            "signatures_valid": verification.get("signatures_valid") == verification.get("total_signatures"),
            "chain_version": CHAIN_VERSION,
            "signature_scheme": SIGNATURE_SCHEME,
            "signer_id": SIGNER_ID,
            "legacy_recovered": self.legacy_recovered,
            "verification_result": verification,
        }
