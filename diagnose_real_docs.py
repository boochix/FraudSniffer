"""Diagnostic script: Process the 2 real documents and report every fraud signal that fires."""
import sys
import os
import json
import logging

# Set up detailed logging
logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pathlib import Path
from fraudsniffer.pipeline import FraudSnifferService

# Use a fresh temp data directory so historical data doesn't interfere
import tempfile
data_dir = Path(tempfile.mkdtemp(prefix="fraudsniffer_diag_"))
service = FraudSnifferService(root_dir=data_dir)

real_doc_dir = Path(r"c:\Users\Acer\Downloads\canara\real doc")
pdfs = sorted(real_doc_dir.glob("*.pdf"))

print(f"\n{'='*80}")
print(f"FRAUDSNIFFER REAL DOCUMENT DIAGNOSTIC")
print(f"{'='*80}")
print(f"Found {len(pdfs)} real documents to test:\n")

for pdf in pdfs:
    print(f"\n{'─'*80}")
    print(f"FILE: {pdf.name}")
    print(f"SIZE: {pdf.stat().st_size:,} bytes")
    print(f"{'─'*80}")
    
    try:
        result = service.process_file(pdf, metadata={})
        
        print(f"\n  FRAUD SCORE:    {result.fraud_score:.4f}  ({result.fraud_score*100:.1f}%)")
        print(f"  STATE:          {result.state.value}")
        print(f"  UI LABEL:       {result.ui_state_label}")
        print(f"  DOC TYPE:       {result.document_type} (confidence: {result.classification_confidence})")
        print(f"  OCR CONFIDENCE: {result.ocr_confidence}")
        print(f"  SUMMARY:        {result.final_reason_summary}")
        
        print(f"\n  REASON CODES ({len(result.risk_decision_reason_codes)}):")
        for rc in result.risk_decision_reason_codes:
            print(f"    ❌ {rc}")
        
        print(f"\n  CONFIDENCE BREAKDOWN (each contributor to fraud score):")
        for key, val in sorted(result.confidence_breakdown.items(), key=lambda x: -x[1]):
            print(f"    {key:40s} = {val:.4f}  ({val*100:.1f}%)")
        
        print(f"\n  OCR WARNINGS:")
        for w in (result.ocr_warnings or []):
            print(f"    ⚠ {w}")
        
        print(f"\n  ALL WARNINGS:")
        for w in (result.warnings or []):
            print(f"    ⚠ {w}")
        
        # Feature status
        print(f"\n  FEATURE STATUS:")
        for fname, fstatus in sorted((result.feature_status or {}).items()):
            print(f"    {fname:40s} = {fstatus}")
        
        # Feature values - what was actually extracted
        print(f"\n  KEY EXTRACTED VALUES:")
        fv = result.feature_values or {}
        for key in ["employee_name", "employer_name", "salary_amount", "document_date",
                     "company_name", "designation", "pan_number", "ifsc_code", "bank_account",
                     "arithmetic_valid", "arithmetic_log", "ml_structural_anomaly_score",
                     "salary_deviation_msg"]:
            if key in fv:
                print(f"    {key:40s} = {fv[key]}")
        
        # External verification
        print(f"\n  EXTERNAL VERIFICATION:")
        ext = result.external_verification or {}
        for vname, vresult in ext.items():
            status = "✅ VALID" if vresult.get("valid") else "❌ FAILED"
            error = vresult.get("error", "")
            print(f"    {vname:20s}: {status}  {error}")
        
        # Advanced forensics summary
        print(f"\n  ADVANCED FORENSICS:")
        af = result.advanced_forensics or {}
        
        # Visual / ELA
        ela = af.get("visual", {}).get("ela", {})
        print(f"    ELA triggered:     {ela.get('triggered')}  (max_score: {ela.get('max_score')}, threshold: {ela.get('threshold')})")
        
        # PDF forensics
        pdf_f = af.get("pdf", {})
        font_audit = pdf_f.get("font_audit", {})
        obj_audit = pdf_f.get("object_audit", {})
        print(f"    Font audit:        triggered={font_audit.get('triggered')}  score={font_audit.get('score')}  anomalies={len(font_audit.get('anomalies', []))}")
        if font_audit.get("anomalies"):
            for fa in font_audit["anomalies"][:3]:
                print(f"      - text='{fa.get('text', '')[:40]}' font={fa.get('font')} dom={fa.get('dominant_font')} size={fa.get('size')} med={fa.get('median_size')}")
        print(f"    Object audit:      triggered={obj_audit.get('triggered')}  score={obj_audit.get('score')}  anomalies={obj_audit.get('anomalies', [])}")
        
        # Adversarial text
        adv = af.get("adversarial_text", {})
        hidden = adv.get("hidden_text", {})
        raw_div = adv.get("raw_ocr_divergence", {})
        print(f"    Hidden text:       triggered={hidden.get('triggered')}  spans={hidden.get('hidden_span_count')}  unicode={hidden.get('hidden_unicode_count')}")
        if hidden.get("hidden_spans"):
            for hs in hidden["hidden_spans"][:3]:
                print(f"      - text='{hs.get('text', '')[:40]}' font={hs.get('font')} size={hs.get('size')} color={hs.get('color')}")
        print(f"    Raw OCR div:       triggered={raw_div.get('triggered')}  distance={raw_div.get('distance')}  score={raw_div.get('score')}")
        
        # Behavioral risks
        print(f"\n  BEHAVIORAL RISKS: {result.behavioral_risks}")
        
        # Similarity matches
        print(f"  SIMILARITY MATCHES: {result.similarity_matches}")
        
        # Seal evidence
        seal = result.seal_evidence
        if seal:
            print(f"\n  SEAL EVIDENCE:")
            print(f"    phash distance: {seal.seal_phash_distance}")
            print(f"    raw hamming:    {seal.raw_hamming_distance}")
            print(f"    feature status: {seal.feature_status}")
            print(f"    evidence:       {seal.evidence}")
        
    except Exception as e:
        import traceback
        print(f"\n  ERROR PROCESSING: {e}")
        traceback.print_exc()

print(f"\n{'='*80}")
print(f"DIAGNOSTIC COMPLETE")
print(f"{'='*80}")
