import base64
import json

from fraudsniffer.pipeline import FraudSnifferService
from fraudsniffer.pqc_audit import (
    CHAIN_VERSION,
    SIGNATURE_SCHEME,
    SIGNER_ID,
    HMACAuditSigner,
    PQCAuditTrail,
)
from fraudsniffer.web_app import create_app


def _read_chain(audit_dir):
    return json.loads((audit_dir / "audit_chain.json").read_text(encoding="utf-8"))


def _write_chain(audit_dir, chain):
    (audit_dir / "audit_chain.json").write_text(json.dumps(chain, indent=2), encoding="utf-8")


def test_hmac_audit_signer_roundtrip_and_tamper_rejection():
    pk, sk = HMACAuditSigner.generate_keypair()
    payload_hash = b"abc123"
    signature = HMACAuditSigner.sign(payload_hash, sk)

    assert HMACAuditSigner.verify(payload_hash, signature, pk, sk) is True
    assert HMACAuditSigner.verify(b"changed", signature, pk, sk) is False

    other_pk, other_sk = HMACAuditSigner.generate_keypair()
    assert HMACAuditSigner.verify(payload_hash, signature, other_pk, other_sk) is False


def test_fresh_v2_chain_has_metadata_and_verifies(tmp_path):
    audit_dir = tmp_path / "pqc"
    trail = PQCAuditTrail(audit_dir)
    trail.record_event("doc_1", "UPLOADED", {"path": "sample.txt"})

    result = trail.verify_chain_integrity()
    chain = _read_chain(audit_dir)

    assert result["ok"] is True
    assert result["verification_percentage"] == 100.0
    assert chain[0]["details"]["event"] == "GENESIS"
    assert chain[0]["details"]["created_by"] == "FraudSniffer"
    assert chain[0]["details"]["chain_version"] == CHAIN_VERSION
    assert chain[0]["details"]["signature_scheme"] == SIGNATURE_SCHEME
    assert chain[0]["details"]["signer_id"] == SIGNER_ID

    signed = chain[1]
    assert signed["signed_at"]
    assert signed["payload_hash"]
    assert signed["signature"]
    assert signed["signature_scheme"] == SIGNATURE_SCHEME
    assert signed["signer_id"] == SIGNER_ID


def test_persistent_key_reload_verifies_existing_chain(tmp_path):
    audit_dir = tmp_path / "pqc"
    first = PQCAuditTrail(audit_dir)
    first.record_event("doc_1", "UPLOADED", {"path": "sample.txt"})
    first.record_event("doc_1", "HASHED", {"file_hash_sha3": "abc"})

    second = PQCAuditTrail(audit_dir)
    result = second.verify_chain_integrity()

    assert result["ok"] is True
    assert result["blocks_verified"] == result["total_blocks"]
    assert result["signatures_valid"] == result["total_signatures"]


def test_hash_link_tamper_returns_hash_link_failure(tmp_path):
    audit_dir = tmp_path / "pqc"
    trail = PQCAuditTrail(audit_dir)
    trail.record_event("doc_1", "UPLOADED", {"path": "sample.txt"})
    trail.record_event("doc_1", "HASHED", {"file_hash_sha3": "abc"})

    chain = _read_chain(audit_dir)
    chain[2]["previous_hash"] = "bad"
    _write_chain(audit_dir, chain)

    result = trail.verify_chain_integrity()
    assert result["ok"] is False
    assert result["failed_block"] == 2
    assert result["failure_type"] == "hash_link"
    assert result["verification_failed_at"]


def test_signature_tamper_returns_signature_failure(tmp_path):
    audit_dir = tmp_path / "pqc"
    trail = PQCAuditTrail(audit_dir)
    trail.record_event("doc_1", "UPLOADED", {"path": "sample.txt"})

    chain = _read_chain(audit_dir)
    sig = json.loads(base64.b64decode(chain[1]["signature"]).decode("utf-8"))
    sig["digest_b64"] = base64.b64encode(b"invalid-digest").decode("ascii")
    chain[1]["signature"] = base64.b64encode(json.dumps(sig, sort_keys=True).encode("utf-8")).decode("ascii")
    _write_chain(audit_dir, chain)

    result = trail.verify_chain_integrity()
    assert result["ok"] is False
    assert result["failed_block"] == 1
    assert result["failure_type"] == "signature"


def test_unsupported_scheme_returns_unsupported_scheme_failure(tmp_path):
    audit_dir = tmp_path / "pqc"
    trail = PQCAuditTrail(audit_dir)
    trail.record_event("doc_1", "UPLOADED", {"path": "sample.txt"})

    chain = _read_chain(audit_dir)
    chain[1]["signature_scheme"] = "legacy-v1"
    _write_chain(audit_dir, chain)

    result = trail.verify_chain_integrity()
    assert result["ok"] is False
    assert result["failed_block"] == 1
    assert result["failure_type"] == "unsupported_scheme"


def test_legacy_chain_is_backed_up_and_reset(tmp_path):
    audit_dir = tmp_path / "pqc"
    audit_dir.mkdir()
    (audit_dir / "audit_keys.json").write_text(json.dumps({"pk": "old", "sk": "old"}), encoding="utf-8")
    (audit_dir / "audit_chain.json").write_text(
        json.dumps([
            {
                "index": 0,
                "timestamp": 1,
                "doc_id": "genesis",
                "event_type": "GENESIS",
                "details": {"message": "old"},
                "previous_hash": "0" * 64,
            }
        ]),
        encoding="utf-8",
    )

    trail = PQCAuditTrail(audit_dir)
    result = trail.verify_chain_integrity()

    assert trail.legacy_recovered is True
    assert result["ok"] is True
    assert _read_chain(audit_dir)[0]["details"]["chain_version"] == CHAIN_VERSION
    assert list(audit_dir.glob("audit_chain.legacy.*.json.bak"))
    assert list(audit_dir.glob("audit_keys.legacy.*.json.bak"))


def test_corrupted_key_file_is_backed_up_and_chain_resets(tmp_path):
    audit_dir = tmp_path / "pqc"
    first = PQCAuditTrail(audit_dir)
    first.record_event("doc_1", "UPLOADED", {"path": "sample.txt"})
    (audit_dir / "audit_keys.json").write_text("{not valid json", encoding="utf-8")

    recovered = PQCAuditTrail(audit_dir)
    result = recovered.verify_chain_integrity()
    chain = _read_chain(audit_dir)

    assert recovered.legacy_recovered is True
    assert result["ok"] is True
    assert len(chain) == 1
    assert chain[0]["event_type"] == "GENESIS"
    assert list(audit_dir.glob("audit_chain.legacy.*.json.bak"))
    assert list(audit_dir.glob("audit_keys.legacy.*.json.bak"))


def test_health_and_audit_api_return_pqc_diagnostics(tmp_path):
    service = FraudSnifferService(root_dir=tmp_path / "data", db_path=tmp_path / "fraud.db")
    doc = tmp_path / "payslip.txt"
    doc.write_text(
        "Employee Name: Priya Rao\nEmployer: Canara Tech\nSalary: 48000\nDate: 2026-05-01",
        encoding="utf-8",
    )
    service.process_file(doc, {"doc_type": "PAYSLIP"}, doc_id="doc_api_pqc")

    app = create_app(service)
    client = app.test_client()

    health = client.get("/api/health").get_json()
    assert health["pqc_diagnostics"]["keys_loaded"] is True
    assert health["pqc_diagnostics"]["signature_roundtrip_ok"] is True

    audit = client.get("/api/documents/doc_api_pqc/audit_trail").get_json()
    assert audit["pqc_integrity_ok"] is True
    assert audit["verification_result"]["ok"] is True
    assert audit["verification_stats"]["verification_percentage"] == 100.0
    assert audit["pqc_audit_trail"][0]["payload_hash"]
    assert audit["pqc_audit_trail"][0]["signature_scheme"] == SIGNATURE_SCHEME
