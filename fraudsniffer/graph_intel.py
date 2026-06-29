"""
Neo4j Fraud Intelligence Graph Module
======================================

Provides graph-based fraud ring detection, network traversal, and risk
propagation on top of a Neo4j knowledge graph.  Every applicant, document,
employer, device, IP address, bank account, PAN, phone, email, and GSTIN
is modelled as a node; relationships capture the connections discovered
during document processing.

**Graceful degradation**: if the ``neo4j`` Python driver is not installed
or the server is unreachable the module silently falls back to a disabled
stub – no import error, no runtime crash.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Conditional import – the module MUST load even without the neo4j package.
# ---------------------------------------------------------------------------
try:
    from neo4j import GraphDatabase  # type: ignore[import-untyped]
    from neo4j.exceptions import (  # type: ignore[import-untyped]
        AuthError,
        ServiceUnavailable,
        SessionExpired,
        Neo4jError,
    )

    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    GraphDatabase = None  # type: ignore[assignment,misc]

    # Thin shims so type-checking and except-clauses don't explode.
    class _Neo4jStubError(Exception):
        pass

    AuthError = _Neo4jStubError  # type: ignore[assignment,misc]
    ServiceUnavailable = _Neo4jStubError  # type: ignore[assignment,misc]
    SessionExpired = _Neo4jStubError  # type: ignore[assignment,misc]
    Neo4jError = _Neo4jStubError  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_RISK_DECAY = {1: 0.6, 2: 0.3, 3: 0.1}

# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class FraudGraphIntel:
    """High-level façade for the Neo4j fraud intelligence graph.

    Parameters
    ----------
    uri : str
        Bolt URI for the Neo4j instance (default ``bolt://localhost:7687``).
    user : str
        Neo4j username (default ``neo4j``).
    password : str
        Neo4j password (default ``fraudsniffer``).

    Attributes
    ----------
    available : bool
        ``True`` when the driver connected successfully **and** schema
        constraints have been applied.  Every public method short-circuits
        to a safe empty default when ``available is False``.
    """

    # ------------------------------------------------------------------ init
    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "fraudsniffer",
    ) -> None:
        self.available: bool = False
        self._driver = None

        if not NEO4J_AVAILABLE:
            logger.warning(
                "neo4j Python driver is not installed – graph intelligence disabled. "
                "Install with: pip install neo4j"
            )
            return

        try:
            self._driver = GraphDatabase.driver(uri, auth=(user, password))
            # Verify connectivity immediately so we fail fast.
            self._driver.verify_connectivity()
            logger.info("Connected to Neo4j at %s", uri)
            self.available = True
        except (ServiceUnavailable, AuthError, OSError) as exc:
            logger.warning(
                "Neo4j connection failed (%s) – graph intelligence disabled.",
                exc,
            )
            self._driver = None
            return
        except Exception as exc:  # pragma: no cover – unexpected driver errors
            logger.warning(
                "Unexpected Neo4j error (%s) – graph intelligence disabled.",
                exc,
            )
            self._driver = None
            return

        # Apply schema idempotently.
        try:
            self._ensure_schema()
        except Exception as exc:
            logger.warning("Schema setup failed (%s) – continuing anyway.", exc)

    # -------------------------------------------------------------- helpers
    def _run_query(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None,
        *,
        write: bool = False,
    ) -> List[Dict[str, Any]]:
        """Execute a Cypher query and return the list of record dicts.

        For write transactions uses ``execute_write``; for reads uses
        ``execute_read``.  All Neo4j exceptions are caught, logged, and
        result in an empty list so callers never crash.
        """
        if not self.available or self._driver is None:
            return []

        def _work(tx, q=query, p=parameters):
            result = tx.run(q, parameters=p or {})
            return [record.data() for record in result]

        try:
            with self._driver.session() as session:
                if write:
                    return session.execute_write(_work)
                return session.execute_read(_work)
        except (ServiceUnavailable, SessionExpired) as exc:
            logger.error("Neo4j session error: %s", exc)
            return []
        except Neo4jError as exc:
            logger.error("Neo4j query error: %s\nQuery: %s", exc, query[:300])
            return []
        except Exception as exc:  # pragma: no cover
            logger.error("Unexpected error running Cypher: %s", exc)
            return []

    def _run_write(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Convenience wrapper for write transactions."""
        return self._run_query(query, parameters, write=True)

    # --------------------------------------------------------------- schema
    def _ensure_schema(self) -> None:
        """Create uniqueness constraints and performance indexes.

        Uses ``CREATE CONSTRAINT … IF NOT EXISTS`` / ``CREATE INDEX … IF NOT
        EXISTS`` so the method is fully idempotent and safe to call on every
        startup.
        """
        if not self.available:
            return

        constraints = [
            ("Applicant",    "pan",         "applicant_pan_unique"),
            ("Document",     "doc_id",      "document_doc_id_unique"),
            ("Employer",     "name",        "employer_name_unique"),
            ("BankAccount",  "account_no",  "bankaccount_account_no_unique"),
            ("Device",       "fingerprint", "device_fingerprint_unique"),
            ("IPAddress",    "address",     "ipaddress_address_unique"),
            ("PAN",          "number",      "pan_number_unique"),
            ("Phone",        "number",      "phone_number_unique"),
            ("Email",        "address",     "email_address_unique"),
            ("GSTIN",        "number",      "gstin_number_unique"),
        ]
        for label, prop, cname in constraints:
            cypher = (
                f"CREATE CONSTRAINT {cname} IF NOT EXISTS "
                f"FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
            )
            self._run_write(cypher)

        indexes = [
            ("Document", "fraud_score",  "idx_document_fraud_score"),
            ("Document", "risk_state",   "idx_document_risk_state"),
            ("Applicant", "name",        "idx_applicant_name"),
        ]
        for label, prop, iname in indexes:
            cypher = (
                f"CREATE INDEX {iname} IF NOT EXISTS "
                f"FOR (n:{label}) ON (n.{prop})"
            )
            self._run_write(cypher)

        logger.info("Neo4j schema constraints and indexes ensured.")

    # ------------------------------------------------------------- ingestion
    def ingest_case(
        self,
        doc_id: str,
        risk_data: Dict[str, Any],
        telemetry_data: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> bool:
        """Ingest a processed fraud-detection case into the graph.

        Parameters
        ----------
        doc_id : str
            Unique document identifier.
        risk_data : dict
            Output of ``RiskResult.to_dict()`` – contains fraud_score, state,
            confidence_breakdown, feature_values, reason_codes, etc.
        telemetry_data : dict
            Output of ``TelemetryData.to_dict()`` – canvas_fingerprint,
            ip_address, vpn_detected, platform, user_agent.
        metadata : dict
            Raw submission metadata – may contain pan_number, bank_account,
            ifsc_code, gstin, cin, employee_name, employer_name.

        Returns
        -------
        bool
            ``True`` if the case was ingested successfully.
        """
        if not self.available:
            return False

        try:
            # ── Extract fields ────────────────────────────────────
            feature_values = risk_data.get("feature_values") or {}

            employee_name = (
                metadata.get("employee_name")
                or feature_values.get("employee_name")
                or ""
            )
            employer_name = (
                metadata.get("employer_name")
                or feature_values.get("employer_name")
                or ""
            )
            salary_amount = feature_values.get("salary_amount")
            pan_number = metadata.get("pan_number") or ""
            bank_account = metadata.get("bank_account") or ""
            ifsc_code = metadata.get("ifsc_code") or ""
            gstin = metadata.get("gstin") or ""

            fraud_score = float(risk_data.get("fraud_score", 0.0))
            risk_state = risk_data.get("state", "UNKNOWN")
            reason_codes = risk_data.get("risk_decision_reason_codes", [])
            document_type = risk_data.get("document_type", "UNKNOWN")

            canvas_fingerprint = telemetry_data.get("canvas_fingerprint", "")
            ip_address = telemetry_data.get("ip_address", "")
            vpn_detected = bool(telemetry_data.get("vpn_detected", False))
            platform = telemetry_data.get("platform", "")
            user_agent = telemetry_data.get("user_agent", "")

            timestamp = time.time()

            # ── Applicant node ────────────────────────────────────
            # PAN is the uniqueness key; fall back to a hash of the
            # employee name if PAN is unavailable.
            applicant_key = pan_number or hashlib.sha256(
                employee_name.encode()
            ).hexdigest()[:16]

            self._run_write(
                """
                MERGE (a:Applicant {pan: $pan})
                ON CREATE SET a.name          = $name,
                              a.created_at    = $ts
                ON MATCH  SET a.name          = CASE WHEN $name <> '' THEN $name ELSE a.name END,
                              a.updated_at    = $ts
                """,
                {"pan": applicant_key, "name": employee_name, "ts": timestamp},
            )

            # ── Document node ─────────────────────────────────────
            self._run_write(
                """
                MERGE (d:Document {doc_id: $doc_id})
                ON CREATE SET d.fraud_score   = $fraud_score,
                              d.risk_state    = $risk_state,
                              d.reason_codes  = $reason_codes,
                              d.document_type = $document_type,
                              d.created_at    = $ts
                ON MATCH  SET d.fraud_score   = $fraud_score,
                              d.risk_state    = $risk_state,
                              d.reason_codes  = $reason_codes,
                              d.document_type = $document_type,
                              d.updated_at    = $ts
                """,
                {
                    "doc_id": doc_id,
                    "fraud_score": fraud_score,
                    "risk_state": risk_state,
                    "reason_codes": reason_codes,
                    "document_type": document_type,
                    "ts": timestamp,
                },
            )

            # ── SUBMITTED relationship (Applicant → Document) ─────
            self._run_write(
                """
                MATCH (a:Applicant {pan: $pan})
                MATCH (d:Document  {doc_id: $doc_id})
                MERGE (a)-[r:SUBMITTED]->(d)
                ON CREATE SET r.salary_claimed = $salary,
                              r.submitted_at   = $ts
                ON MATCH  SET r.salary_claimed = $salary,
                              r.updated_at     = $ts
                """,
                {
                    "pan": applicant_key,
                    "doc_id": doc_id,
                    "salary": salary_amount,
                    "ts": timestamp,
                },
            )

            # ── Employer node & relationship ──────────────────────
            if employer_name:
                self._run_write(
                    """
                    MERGE (e:Employer {name: $name})
                    ON CREATE SET e.created_at = $ts
                    WITH e
                    MATCH (d:Document {doc_id: $doc_id})
                    MERGE (d)-[r:EXTRACTED_FROM]->(e)
                    ON CREATE SET r.created_at = $ts
                    """,
                    {"name": employer_name, "doc_id": doc_id, "ts": timestamp},
                )
                self._run_write(
                    """
                    MATCH (a:Applicant {pan: $pan})
                    MATCH (e:Employer {name: $employer})
                    MERGE (a)-[r:REGISTERED_WITH]->(e)
                    ON CREATE SET r.created_at = $ts
                    """,
                    {
                        "pan": applicant_key,
                        "employer": employer_name,
                        "ts": timestamp,
                    },
                )

            # ── Device node ───────────────────────────────────────
            if canvas_fingerprint:
                self._run_write(
                    """
                    MERGE (dev:Device {fingerprint: $fp})
                    ON CREATE SET dev.platform   = $platform,
                                  dev.user_agent = $user_agent,
                                  dev.created_at = $ts
                    ON MATCH  SET dev.platform   = $platform,
                                  dev.user_agent = $user_agent,
                                  dev.updated_at = $ts
                    WITH dev
                    MATCH (a:Applicant {pan: $pan})
                    MERGE (a)-[r:USES]->(dev)
                    ON CREATE SET r.created_at = $ts
                    """,
                    {
                        "fp": canvas_fingerprint,
                        "platform": platform,
                        "user_agent": user_agent,
                        "pan": applicant_key,
                        "ts": timestamp,
                    },
                )

            # ── IPAddress node ────────────────────────────────────
            if ip_address:
                self._run_write(
                    """
                    MERGE (ip:IPAddress {address: $addr})
                    ON CREATE SET ip.vpn_detected = $vpn,
                                  ip.created_at   = $ts
                    ON MATCH  SET ip.vpn_detected = $vpn,
                                  ip.updated_at   = $ts
                    WITH ip
                    MATCH (a:Applicant {pan: $pan})
                    MERGE (a)-[r:CONNECTED_TO]->(ip)
                    ON CREATE SET r.created_at = $ts
                    """,
                    {
                        "addr": ip_address,
                        "vpn": vpn_detected,
                        "pan": applicant_key,
                        "ts": timestamp,
                    },
                )

            # ── BankAccount node ──────────────────────────────────
            if bank_account:
                self._run_write(
                    """
                    MERGE (ba:BankAccount {account_no: $acct})
                    ON CREATE SET ba.ifsc_code  = $ifsc,
                                  ba.created_at = $ts
                    ON MATCH  SET ba.ifsc_code  = $ifsc,
                                  ba.updated_at = $ts
                    WITH ba
                    MATCH (a:Applicant {pan: $pan})
                    MERGE (a)-[r:OWNS]->(ba)
                    ON CREATE SET r.created_at = $ts
                    """,
                    {
                        "acct": bank_account,
                        "ifsc": ifsc_code,
                        "pan": applicant_key,
                        "ts": timestamp,
                    },
                )

            # ── PAN node ──────────────────────────────────────────
            if pan_number:
                self._run_write(
                    """
                    MERGE (p:PAN {number: $num})
                    ON CREATE SET p.created_at = $ts
                    WITH p
                    MATCH (a:Applicant {pan: $pan})
                    MERGE (a)-[r:OWNS]->(p)
                    ON CREATE SET r.created_at = $ts
                    """,
                    {
                        "num": pan_number,
                        "pan": applicant_key,
                        "ts": timestamp,
                    },
                )

            # ── GSTIN node ────────────────────────────────────────
            if gstin:
                self._run_write(
                    """
                    MERGE (g:GSTIN {number: $num})
                    ON CREATE SET g.created_at = $ts
                    WITH g
                    MATCH (a:Applicant {pan: $pan})
                    MERGE (a)-[r:OWNS]->(g)
                    ON CREATE SET r.created_at = $ts
                    """,
                    {"num": gstin, "pan": applicant_key, "ts": timestamp},
                )

            logger.info("Ingested case %s into Neo4j graph.", doc_id)
            return True

        except Exception as exc:
            logger.error("Failed to ingest case %s: %s", doc_id, exc)
            return False

    # ========================================================= ring detection
    def detect_fraud_rings(self) -> List[Dict[str, Any]]:
        """Run all ring-detection heuristics and return a unified list.

        Each dict contains:
        - ``ring_id``   – deterministic identifier
        - ``ring_type`` – e.g. ``SHARED_DEVICE``, ``SHARED_PAN``, …
        - ``members``   – list of applicant names / pans
        - ``shared_nodes`` – the shared entity values
        - ``ring_risk`` – aggregate risk score for the ring
        """
        if not self.available:
            return []

        rings: List[Dict[str, Any]] = []
        rings.extend(self.detect_shared_devices())
        rings.extend(self.detect_shared_pans())
        rings.extend(self.detect_shared_bank_accounts())
        rings.extend(self.detect_employer_laundering())
        rings.extend(self.detect_salary_inflation_clusters())
        return rings

    def detect_shared_devices(self) -> List[Dict[str, Any]]:
        """Applicants sharing the same canvas fingerprint (≥ 3)."""
        if not self.available:
            return []

        records = self._run_query(
            """
            MATCH (a:Applicant)-[:USES]->(dev:Device)
            WITH dev, collect(DISTINCT a.name) AS members, collect(DISTINCT a.pan) AS pans
            WHERE size(members) >= 3
            RETURN dev.fingerprint AS fingerprint,
                   members,
                   pans,
                   size(members) AS member_count
            ORDER BY member_count DESC
            """
        )

        rings: List[Dict[str, Any]] = []
        for rec in records:
            ring_id = f"DEVICE_{hashlib.sha256(rec['fingerprint'].encode()).hexdigest()[:12]}"
            rings.append(
                {
                    "ring_id": ring_id,
                    "ring_type": "SHARED_DEVICE",
                    "members": rec["members"],
                    "member_pans": rec["pans"],
                    "shared_nodes": [rec["fingerprint"]],
                    "ring_risk": min(1.0, 0.3 * rec["member_count"]),
                }
            )
        return rings

    def detect_shared_pans(self) -> List[Dict[str, Any]]:
        """Multiple applicants using the same PAN number."""
        if not self.available:
            return []

        records = self._run_query(
            """
            MATCH (a:Applicant)-[:OWNS]->(p:PAN)
            WITH p, collect(DISTINCT a.name) AS members, collect(DISTINCT a.pan) AS pans
            WHERE size(members) >= 2
            RETURN p.number   AS pan_number,
                   members,
                   pans,
                   size(members) AS member_count
            ORDER BY member_count DESC
            """
        )

        rings: List[Dict[str, Any]] = []
        for rec in records:
            ring_id = f"PAN_{hashlib.sha256(rec['pan_number'].encode()).hexdigest()[:12]}"
            rings.append(
                {
                    "ring_id": ring_id,
                    "ring_type": "SHARED_PAN",
                    "members": rec["members"],
                    "member_pans": rec["pans"],
                    "shared_nodes": [rec["pan_number"]],
                    "ring_risk": min(1.0, 0.5 * rec["member_count"]),
                }
            )
        return rings

    def detect_shared_bank_accounts(self) -> List[Dict[str, Any]]:
        """Multiple applicants owning the same bank account."""
        if not self.available:
            return []

        records = self._run_query(
            """
            MATCH (a:Applicant)-[:OWNS]->(ba:BankAccount)
            WITH ba, collect(DISTINCT a.name) AS members, collect(DISTINCT a.pan) AS pans
            WHERE size(members) >= 2
            RETURN ba.account_no AS account_no,
                   members,
                   pans,
                   size(members) AS member_count
            ORDER BY member_count DESC
            """
        )

        rings: List[Dict[str, Any]] = []
        for rec in records:
            ring_id = f"BANK_{hashlib.sha256(rec['account_no'].encode()).hexdigest()[:12]}"
            rings.append(
                {
                    "ring_id": ring_id,
                    "ring_type": "SHARED_BANK_ACCOUNT",
                    "members": rec["members"],
                    "member_pans": rec["pans"],
                    "shared_nodes": [rec["account_no"]],
                    "ring_risk": min(1.0, 0.5 * rec["member_count"]),
                }
            )
        return rings

    def detect_employer_laundering(self) -> List[Dict[str, Any]]:
        """Employers with ≥ 3 flagged documents from different applicants."""
        if not self.available:
            return []

        records = self._run_query(
            """
            MATCH (a:Applicant)-[:SUBMITTED]->(d:Document)-[:EXTRACTED_FROM]->(e:Employer)
            WHERE d.risk_state IN ['SUSPECT', 'BLOCK']
            WITH e,
                 collect(DISTINCT a.name) AS members,
                 collect(DISTINCT a.pan)  AS pans,
                 collect(DISTINCT d.doc_id) AS doc_ids,
                 avg(d.fraud_score) AS avg_score
            WHERE size(members) >= 3
            RETURN e.name       AS employer,
                   members,
                   pans,
                   doc_ids,
                   avg_score,
                   size(members) AS member_count
            ORDER BY avg_score DESC
            """
        )

        rings: List[Dict[str, Any]] = []
        for rec in records:
            ring_id = f"EMPLOYER_{hashlib.sha256(rec['employer'].encode()).hexdigest()[:12]}"
            rings.append(
                {
                    "ring_id": ring_id,
                    "ring_type": "EMPLOYER_LAUNDERING",
                    "members": rec["members"],
                    "member_pans": rec["pans"],
                    "shared_nodes": [rec["employer"]],
                    "flagged_doc_ids": rec["doc_ids"],
                    "ring_risk": min(1.0, float(rec["avg_score"] or 0)),
                }
            )
        return rings

    def detect_salary_inflation_clusters(self) -> List[Dict[str, Any]]:
        """Applicants at the same employer whose salary is ≥ 2× the median.

        Returns clusters where at least 2 applicants have inflated
        salaries relative to the employer median.
        """
        if not self.available:
            return []

        records = self._run_query(
            """
            MATCH (a:Applicant)-[r:SUBMITTED]->(d:Document)-[:EXTRACTED_FROM]->(e:Employer)
            WHERE r.salary_claimed IS NOT NULL
            WITH e,
                 collect({name: a.name, pan: a.pan, salary: r.salary_claimed,
                          score: d.fraud_score}) AS entries
            WHERE size(entries) >= 3
            RETURN e.name AS employer, entries
            """
        )

        rings: List[Dict[str, Any]] = []
        for rec in records:
            entries = rec["entries"]
            salaries = sorted([e["salary"] for e in entries if e["salary"] is not None])
            if len(salaries) < 3:
                continue
            median = salaries[len(salaries) // 2]
            if median <= 0:
                continue

            inflated = [e for e in entries if e["salary"] and e["salary"] >= median * 2]
            if len(inflated) < 2:
                continue

            ring_id = f"SALARY_{hashlib.sha256(rec['employer'].encode()).hexdigest()[:12]}"
            rings.append(
                {
                    "ring_id": ring_id,
                    "ring_type": "SALARY_INFLATION",
                    "members": [e["name"] for e in inflated],
                    "member_pans": [e["pan"] for e in inflated],
                    "shared_nodes": [rec["employer"]],
                    "median_salary": median,
                    "inflated_salaries": [e["salary"] for e in inflated],
                    "ring_risk": min(
                        1.0,
                        sum(float(e.get("score") or 0) for e in inflated)
                        / max(len(inflated), 1),
                    ),
                }
            )
        return rings

    # ==================================================== network traversal
    def get_network_for_document(
        self, doc_id: str, max_hops: int = 3
    ) -> Dict[str, Any]:
        """Return the ego-network around a document in Cytoscape.js format.

        Parameters
        ----------
        doc_id : str
            Document to center on.
        max_hops : int
            Maximum relationship depth (default 3).

        Returns
        -------
        dict
            ``{'elements': {'nodes': [...], 'edges': [...]}, 'rings': [...],
            'stats': {'total_nodes': …, 'total_edges': …, 'ring_count': …}}``
        """
        empty: Dict[str, Any] = {
            "elements": {"nodes": [], "edges": []},
            "rings": [],
            "stats": {"total_nodes": 0, "total_edges": 0, "ring_count": 0},
        }
        if not self.available:
            return empty

        # Variable-length path up to max_hops
        records = self._run_query(
            """
            MATCH path = (d:Document {doc_id: $doc_id})-[*1..$max_hops]-(n)
            WITH nodes(path) AS ns, relationships(path) AS rs
            UNWIND ns AS node
            WITH collect(DISTINCT node) AS all_nodes,
                 collect(DISTINCT rs)   AS all_rels_nested
            UNWIND all_rels_nested AS rel_list
            UNWIND rel_list AS rel
            WITH all_nodes, collect(DISTINCT rel) AS all_rels
            RETURN all_nodes, all_rels
            """,
            {"doc_id": doc_id, "max_hops": max_hops},
        )

        cy_nodes: List[Dict[str, Any]] = []
        cy_edges: List[Dict[str, Any]] = []
        seen_node_ids: set = set()
        seen_edge_ids: set = set()

        for rec in records:
            for node in rec.get("all_nodes", []):
                nid = self._node_cyto_id(node)
                if nid not in seen_node_ids:
                    seen_node_ids.add(nid)
                    cy_nodes.append(self._node_to_cyto(node))

            for rel in rec.get("all_rels", []):
                eid = self._rel_cyto_id(rel)
                if eid not in seen_edge_ids:
                    seen_edge_ids.add(eid)
                    cy_edges.append(self._rel_to_cyto(rel))

        # If the variable-length query returned nothing, try a simpler
        # direct-match approach (works better across Neo4j versions).
        if not cy_nodes:
            cy_nodes, cy_edges = self._fallback_network(doc_id, max_hops)

        rings = self.detect_fraud_rings()

        return {
            "elements": {"nodes": cy_nodes, "edges": cy_edges},
            "rings": rings,
            "stats": {
                "total_nodes": len(cy_nodes),
                "total_edges": len(cy_edges),
                "ring_count": len(rings),
            },
        }

    def _fallback_network(
        self, doc_id: str, max_hops: int
    ) -> tuple:
        """Simpler hop-by-hop query for Neo4j versions that struggle with
        parameterised variable-length paths."""
        cy_nodes: List[Dict[str, Any]] = []
        cy_edges: List[Dict[str, Any]] = []
        seen_node_ids: set = set()
        seen_edge_ids: set = set()

        # Hop 1
        records = self._run_query(
            """
            MATCH (d:Document {doc_id: $doc_id})-[r]-(n)
            RETURN d, r, n
            """,
            {"doc_id": doc_id},
        )
        hop1_ids: list[str] = []
        for rec in records:
            for key in ("d", "n"):
                node = rec.get(key)
                if node is None:
                    continue
                nid = self._node_cyto_id(node)
                if nid not in seen_node_ids:
                    seen_node_ids.add(nid)
                    cy_nodes.append(self._node_to_cyto(node))
                    if key == "n":
                        hop1_ids.append(nid)
            rel = rec.get("r")
            if rel is not None:
                eid = self._rel_cyto_id(rel)
                if eid not in seen_edge_ids:
                    seen_edge_ids.add(eid)
                    cy_edges.append(self._rel_to_cyto(rel))

        # Hops 2..max_hops – expand outward from previously discovered nodes
        if max_hops >= 2 and hop1_ids:
            for _ in range(max_hops - 1):
                next_hop_ids: list[str] = []
                for nid in hop1_ids:
                    recs = self._run_query(
                        """
                        MATCH (a)-[r]-(b)
                        WHERE elementId(a) = $eid
                        RETURN a, r, b
                        """,
                        {"eid": nid},
                    )
                    for rec in recs:
                        for key in ("a", "b"):
                            node = rec.get(key)
                            if node is None:
                                continue
                            node_id = self._node_cyto_id(node)
                            if node_id not in seen_node_ids:
                                seen_node_ids.add(node_id)
                                cy_nodes.append(self._node_to_cyto(node))
                                next_hop_ids.append(node_id)
                        rel = rec.get("r")
                        if rel is not None:
                            eid2 = self._rel_cyto_id(rel)
                            if eid2 not in seen_edge_ids:
                                seen_edge_ids.add(eid2)
                                cy_edges.append(self._rel_to_cyto(rel))
                hop1_ids = next_hop_ids
                if not hop1_ids:
                    break

        return cy_nodes, cy_edges

    def get_full_graph(self, limit: int = 200) -> Dict[str, Any]:
        """Return the entire graph (capped at *limit* nodes) in Cytoscape.js
        format for the overview visualization.

        Parameters
        ----------
        limit : int
            Max number of nodes to return (default 200).

        Returns
        -------
        dict
            Same schema as :meth:`get_network_for_document`.
        """
        empty: Dict[str, Any] = {
            "elements": {"nodes": [], "edges": []},
            "rings": [],
            "stats": {"total_nodes": 0, "total_edges": 0, "ring_count": 0},
        }
        if not self.available:
            return empty

        node_records = self._run_query(
            "MATCH (n) RETURN n LIMIT $limit",
            {"limit": limit},
        )

        cy_nodes: List[Dict[str, Any]] = []
        seen_node_ids: set = set()
        for rec in node_records:
            node = rec.get("n")
            if node is None:
                continue
            nid = self._node_cyto_id(node)
            if nid not in seen_node_ids:
                seen_node_ids.add(nid)
                cy_nodes.append(self._node_to_cyto(node))

        edge_records = self._run_query(
            "MATCH ()-[r]->() RETURN r LIMIT $limit",
            {"limit": limit * 2},
        )
        cy_edges: List[Dict[str, Any]] = []
        seen_edge_ids: set = set()
        for rec in edge_records:
            rel = rec.get("r")
            if rel is None:
                continue
            eid = self._rel_cyto_id(rel)
            if eid not in seen_edge_ids:
                seen_edge_ids.add(eid)
                cy_edges.append(self._rel_to_cyto(rel))

        rings = self.detect_fraud_rings()

        return {
            "elements": {"nodes": cy_nodes, "edges": cy_edges},
            "rings": rings,
            "stats": {
                "total_nodes": len(cy_nodes),
                "total_edges": len(cy_edges),
                "ring_count": len(rings),
            },
        }

    # ----------------------------------------------------- cytoscape helpers
    @staticmethod
    def _node_cyto_id(node) -> str:
        """Derive a stable Cytoscape id from a Neo4j node object or dict."""
        # Neo4j Python driver ≥ 5 returns Node objects with element_id
        if hasattr(node, "element_id"):
            return str(node.element_id)
        if hasattr(node, "id"):
            return str(node.id)
        # Dict representation from record.data()
        if isinstance(node, dict):
            for key in ("doc_id", "pan", "name", "fingerprint", "address",
                        "account_no", "number"):
                if key in node:
                    return str(node[key])
            return str(id(node))
        return str(id(node))

    @staticmethod
    def _node_labels(node) -> List[str]:
        if hasattr(node, "labels"):
            return list(node.labels)
        return []

    @staticmethod
    def _node_props(node) -> Dict[str, Any]:
        if hasattr(node, "items"):
            return dict(node.items()) if callable(node.items) else dict(node)
        if isinstance(node, dict):
            return dict(node)
        return {}

    def _node_to_cyto(self, node) -> Dict[str, Any]:
        """Convert a Neo4j node to a Cytoscape.js node element."""
        props = self._node_props(node)
        labels = self._node_labels(node)
        ntype = labels[0] if labels else "Unknown"
        label = (
            props.get("name")
            or props.get("doc_id")
            or props.get("fingerprint")
            or props.get("address")
            or props.get("account_no")
            or props.get("number")
            or ntype
        )
        return {
            "data": {
                "id": self._node_cyto_id(node),
                "type": ntype,
                "label": str(label),
                "risk": props.get("fraud_score"),
                "state": props.get("risk_state"),
                **{k: v for k, v in props.items() if k not in ("id",)},
            }
        }

    @staticmethod
    def _rel_cyto_id(rel) -> str:
        if hasattr(rel, "element_id"):
            return str(rel.element_id)
        if hasattr(rel, "id"):
            return str(rel.id)
        return str(id(rel))

    def _rel_to_cyto(self, rel) -> Dict[str, Any]:
        """Convert a Neo4j relationship to a Cytoscape.js edge element."""
        rtype = rel.type if hasattr(rel, "type") else "RELATED"
        start = (
            str(rel.start_node.element_id)
            if hasattr(rel, "start_node") and hasattr(rel.start_node, "element_id")
            else self._node_cyto_id(getattr(rel, "start_node", {}))
        )
        end = (
            str(rel.end_node.element_id)
            if hasattr(rel, "end_node") and hasattr(rel.end_node, "element_id")
            else self._node_cyto_id(getattr(rel, "end_node", {}))
        )
        props = dict(rel.items()) if hasattr(rel, "items") and callable(rel.items) else {}
        return {
            "data": {
                "id": self._rel_cyto_id(rel),
                "source": start,
                "target": end,
                "type": rtype,
                **props,
            }
        }

    # ====================================================== risk propagation
    def calculate_risk_propagation(
        self, doc_id: str
    ) -> Dict[str, float]:
        """Propagate fraud risk through the graph from a seed document.

        Decay factors:
        - 1 hop: risk × 0.6
        - 2 hops: risk × 0.3
        - 3 hops: risk × 0.1

        Parameters
        ----------
        doc_id : str
            Source document to propagate from.

        Returns
        -------
        dict
            Mapping of ``node_id → propagated_risk``.
        """
        if not self.available:
            return {}

        # Get seed fraud score
        seed = self._run_query(
            "MATCH (d:Document {doc_id: $doc_id}) RETURN d.fraud_score AS score",
            {"doc_id": doc_id},
        )
        if not seed or seed[0].get("score") is None:
            return {}

        base_risk = float(seed[0]["score"])
        propagated: Dict[str, float] = {}

        for hops, decay in _RISK_DECAY.items():
            records = self._run_query(
                """
                MATCH (d:Document {doc_id: $doc_id})
                MATCH path = (d)-[*""" + str(hops) + """]-(n)
                WHERE n <> d
                RETURN DISTINCT
                    labels(n)[0] AS label,
                    coalesce(n.doc_id, n.pan, n.name, n.fingerprint,
                             n.address, n.account_no, n.number,
                             toString(id(n))) AS node_id,
                    n.fraud_score AS existing_score
                """,
                {"doc_id": doc_id},
            )
            for rec in records:
                nid = rec.get("node_id", "")
                if not nid:
                    continue
                risk = round(base_risk * decay, 4)
                existing = rec.get("existing_score")
                if existing is not None:
                    risk = round(max(risk, float(existing)), 4)
                # Keep the highest propagated risk across hops
                if nid not in propagated or risk > propagated[nid]:
                    propagated[nid] = risk

        logger.debug(
            "Risk propagation from %s: %d nodes affected.", doc_id, len(propagated)
        )
        return propagated

    # ========================================================== statistics
    def get_graph_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics about the fraud graph.

        Returns
        -------
        dict
            Keys: ``total_nodes``, ``total_edges``, ``total_documents``,
            ``total_applicants``, ``total_rings``, ``risk_distribution``,
            ``top_connected_entities``.
        """
        empty: Dict[str, Any] = {
            "total_nodes": 0,
            "total_edges": 0,
            "total_documents": 0,
            "total_applicants": 0,
            "total_rings": 0,
            "risk_distribution": {},
            "top_connected_entities": [],
        }
        if not self.available:
            return empty

        # Total counts
        node_count = self._run_query("MATCH (n) RETURN count(n) AS c")
        edge_count = self._run_query("MATCH ()-[r]->() RETURN count(r) AS c")
        doc_count = self._run_query("MATCH (d:Document) RETURN count(d) AS c")
        app_count = self._run_query("MATCH (a:Applicant) RETURN count(a) AS c")

        # Risk distribution
        risk_dist_records = self._run_query(
            """
            MATCH (d:Document)
            WHERE d.risk_state IS NOT NULL
            RETURN d.risk_state AS state, count(d) AS cnt
            ORDER BY cnt DESC
            """
        )
        risk_distribution = {
            rec["state"]: rec["cnt"] for rec in risk_dist_records if rec.get("state")
        }

        # Top connected entities (by degree)
        top_connected = self._run_query(
            """
            MATCH (n)-[r]-()
            WITH n, labels(n)[0] AS label,
                 coalesce(n.name, n.doc_id, n.pan, n.fingerprint,
                          n.address, n.account_no, n.number) AS entity,
                 count(r) AS degree
            RETURN label, entity, degree
            ORDER BY degree DESC
            LIMIT 10
            """
        )

        rings = self.detect_fraud_rings()

        return {
            "total_nodes": node_count[0]["c"] if node_count else 0,
            "total_edges": edge_count[0]["c"] if edge_count else 0,
            "total_documents": doc_count[0]["c"] if doc_count else 0,
            "total_applicants": app_count[0]["c"] if app_count else 0,
            "total_rings": len(rings),
            "risk_distribution": risk_distribution,
            "top_connected_entities": top_connected,
        }

    # ============================================================== cleanup
    def close(self) -> None:
        """Close the Neo4j driver connection and release resources."""
        if self._driver is not None:
            try:
                self._driver.close()
                logger.info("Neo4j driver closed.")
            except Exception as exc:
                logger.warning("Error closing Neo4j driver: %s", exc)
            finally:
                self._driver = None
                self.available = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        # Best-effort cleanup on GC.
        try:
            self.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Singleton factory
# --------------------------------------------------------------------------
_singleton_lock = threading.Lock()
_singleton_instance: Optional[FraudGraphIntel] = None


def get_graph_intel(
    uri: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
) -> FraudGraphIntel:
    """Return (or create) a module-level singleton :class:`FraudGraphIntel`.

    If Neo4j is unreachable the returned instance will have
    ``available = False`` and every method will return safe empty defaults.

    Parameters
    ----------
    uri, user, password : str | None
        Override the default connection parameters.  Only used the *first*
        time the singleton is created.
    """
    global _singleton_instance

    if _singleton_instance is not None:
        return _singleton_instance

    with _singleton_lock:
        # Double-checked locking
        if _singleton_instance is not None:
            return _singleton_instance

        kwargs: Dict[str, str] = {}
        if uri is not None:
            kwargs["uri"] = uri
        if user is not None:
            kwargs["user"] = user
        if password is not None:
            kwargs["password"] = password

        _singleton_instance = FraudGraphIntel(**kwargs)
        return _singleton_instance
