"""Quick diagnostic: key results only."""
import sys, os, tempfile, logging
logging.basicConfig(level=logging.WARNING)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pathlib import Path
from fraudsniffer.pipeline import FraudSnifferService

data_dir = Path(tempfile.mkdtemp(prefix="diag_"))
service = FraudSnifferService(root_dir=data_dir)
real_doc_dir = Path(r"c:\Users\Acer\Downloads\canara\real doc")
pdfs = sorted(real_doc_dir.glob("*.pdf"))
for pdf in pdfs:
    result = service.process_file(pdf, metadata={})
    print(f"FILE: {pdf.name}")
    print(f"  FRAUD SCORE: {result.fraud_score*100:.1f}%")
    print(f"  STATE:       {result.state.value}")
    print(f"  REASONS:     {result.risk_decision_reason_codes}")
    print(f"  SEAL STATUS: {result.seal_evidence.feature_status.value}")
    print(f"  WARNINGS:    {result.warnings}")
    print(f"  CONFIDENCE:  {result.confidence_breakdown}")
    print()
