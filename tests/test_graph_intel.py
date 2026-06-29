import pytest
from unittest.mock import patch, MagicMock
from fraudsniffer.graph_intel import FraudGraphIntel

@patch("fraudsniffer.graph_intel.GraphDatabase")
def test_fraud_graph_intel_initialization(mock_db):
    mock_driver = MagicMock()
    mock_db.driver.return_value = mock_driver

    # Mock successful verify_connectivity
    intel = FraudGraphIntel(uri="bolt://localhost:7687", user="neo4j", password="password")
    assert intel.available is True

@patch("fraudsniffer.graph_intel.GraphDatabase")
def test_fraud_graph_intel_unavailable(mock_db):
    # Mock Neo4j driver throwing exception on verify_connectivity
    mock_driver = MagicMock()
    mock_driver.verify_connectivity.side_effect = Exception("Connection refused")
    mock_db.driver.return_value = mock_driver

    intel = FraudGraphIntel(uri="bolt://localhost:7687", user="neo4j", password="password")
    assert intel.available is False

def test_fraud_graph_intel_graceful_degradation():
    intel = FraudGraphIntel()
    intel.available = False
    
    # These should return empty/default values without crashing when unavailable
    assert intel.ingest_case("doc_123", {}, {}, {}) is False
    assert intel.get_network_for_document("doc_123") == {
        'elements': {'edges': [], 'nodes': []},
        'rings': [],
        'stats': {'ring_count': 0, 'total_edges': 0, 'total_nodes': 0}
    }
    assert intel.detect_fraud_rings() == []
    assert intel.get_graph_stats() == {
        "total_nodes": 0,
        "total_edges": 0,
        "total_documents": 0,
        "total_applicants": 0,
        "total_rings": 0,
        "risk_distribution": {},
        "top_connected_entities": [],
    }
