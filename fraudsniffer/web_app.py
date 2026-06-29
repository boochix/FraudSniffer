from __future__ import annotations

import base64
import io
import logging
import os
import time
from pathlib import Path
from typing import Optional

from .pipeline import FraudSnifferService
from .models import TelemetryData, PipelineState
from .ai_assistant import UnderwriterAssistant

logger = logging.getLogger(__name__)

try:
    from flask import Flask, jsonify, render_template, request, send_file
except Exception:  # pragma: no cover
    Flask = None  # type: ignore


def _placeholder_png(message: str) -> io.BytesIO:
    buffer = io.BytesIO()
    try:
        from PIL import Image, ImageDraw  # type: ignore

        image = Image.new("RGB", (1000, 700), "#f8fafc")
        draw = ImageDraw.Draw(image)
        draw.rectangle((40, 40, 960, 660), outline="#cbd5e1", width=2)
        draw.text((72, 82), "Document preview unavailable", fill="#0f172a")
        draw.text((72, 120), message[:180], fill="#64748b")
        image.save(buffer, "PNG")
    except Exception:
        buffer.write(
            base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4//8/AAX+Av5B4pHRAAAAAElFTkSuQmCC"
            )
        )
    buffer.seek(0)
    return buffer


def create_app(service: FraudSnifferService, api_key: Optional[str] = None):
    if Flask is None:
        raise RuntimeError("Flask is not installed")

    app = Flask(__name__)
    assistant = UnderwriterAssistant()
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
    configured_key = api_key if api_key is not None else os.getenv("FRAUDSNIFFER_API_KEY")
    is_auth_enforced = (configured_key is not None)
    if not configured_key:
        configured_key = "hackathon"

    submit_rate_limit = {}
    last_rate_limit_cleanup = 0.0

    @app.before_request
    def require_basic_auth():
        return None

    @app.before_request
    def limit_submit_rate():
        nonlocal last_rate_limit_cleanup
        if request.path == "/api/documents/submit" and request.method == "POST":
            ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "127.0.0.1"
            now = time.time()
            if now - last_rate_limit_cleanup > 60:
                stale_ips = []
                for key, values in submit_rate_limit.items():
                    recent = [t for t in values if now - t < 60]
                    if recent:
                        submit_rate_limit[key] = recent
                    else:
                        stale_ips.append(key)
                for key in stale_ips:
                    submit_rate_limit.pop(key, None)
                last_rate_limit_cleanup = now
            timestamps = submit_rate_limit.setdefault(ip, [])
            submit_rate_limit[ip] = [t for t in timestamps if now - t < 60]
            if len(submit_rate_limit[ip]) >= 10:
                return jsonify({"error": "rate limit exceeded: max 10 submissions per minute"}), 429
            submit_rate_limit[ip].append(now)
        return None

    @app.after_request
    def disable_browser_caching(response):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    # ── Dashboard ──────────────────────────────────────────────

    @app.get("/")
    def index():
        return render_template("dashboard.html")

    # ── Document Submit ────────────────────────────────────────

    @app.post("/api/documents/submit")
    def submit_document():
        if "file" not in request.files:
            return jsonify({"error": "multipart field 'file' is required"}), 400
        upload = request.files["file"]
        metadata = request.form.get("metadata") or "{}"
        telemetry_raw = request.form.get("telemetry") or "{}"
        import json
        import tempfile

        try:
            metadata_obj = json.loads(metadata)
        except json.JSONDecodeError:
            return jsonify({"error": "metadata must be JSON"}), 400

        # Parse telemetry payload
        try:
            telemetry_dict = json.loads(telemetry_raw)
        except json.JSONDecodeError:
            telemetry_dict = {}

        # Build TelemetryData, injecting server-side IP
        telemetry_dict["ip_address"] = (
            request.headers.get("X-Forwarded-For", request.remote_addr) or "127.0.0.1"
        )
        telemetry = TelemetryData.from_dict(telemetry_dict)

        suffix = Path(upload.filename or "upload.bin").suffix or ".bin"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            upload.save(tmp.name)
            tmp_path = Path(tmp.name)
        try:
            risk = service.process_file(tmp_path, metadata_obj, telemetry=telemetry)
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass
        return jsonify(risk.to_dict())

    # ── Risk Lookup ────────────────────────────────────────────

    @app.get("/api/documents/<doc_id>/risk")
    def document_risk(doc_id: str):
        risk = service.get_risk(doc_id)
        if not risk:
            return jsonify({"error": "document not found"}), 404
        return jsonify(risk)

    # ── Document List (History) ────────────────────────────────

    @app.get("/api/documents")
    def list_documents():
        docs = service.storage.list_documents(limit=200)
        return jsonify(docs)

    @app.get("/api/stats")
    def system_stats():
        import sys
        exclude_offsets = app.testing or "pytest" in sys.modules
        stats = service.storage.get_system_stats(exclude_offsets=exclude_offsets)
        return jsonify(stats)

    @app.post("/api/documents/<doc_id>/assistant/report")
    def assistant_report(doc_id: str):
        risk_result = service.get_risk(doc_id)
        if not risk_result:
            return jsonify({"error": "document not found"}), 404
        report = assistant.generate_report(doc_id, risk_result)
        return jsonify(report)

    @app.post("/api/documents/<doc_id>/assistant/judge-report")
    def assistant_judge_report(doc_id: str):
        """Generate a concise judge-demonstration report optimized for 30-second comprehension."""
        risk_result = service.get_risk(doc_id)
        if not risk_result:
            return jsonify({"error": "document not found"}), 404
        report = assistant.generate_judge_report(doc_id, risk_result)
        return jsonify({"report": report})

    @app.post("/api/documents/<doc_id>/assistant/chat")
    def assistant_chat_post(doc_id: str):
        risk_result = service.get_risk(doc_id)
        if not risk_result:
            return jsonify({"error": "document not found"}), 404
            
        json_data = request.get_json(silent=True) or {}
        message = json_data.get("message", "")
        explain_rule = json_data.get("explain_rule") or request.args.get("explain_rule")
        
        if explain_rule:
            explanation = assistant.generate_explanation(explain_rule, risk_result)
            service.storage.save_chat_message(doc_id, "user", f"Explain finding: {explain_rule}")
            service.storage.save_chat_message(doc_id, "assistant", explanation)
            return jsonify({"message": explanation})
        
        if not message:
            return jsonify({"error": "message is required"}), 400
            
        history = service.storage.get_chat_history(doc_id)
        response = assistant.chat(history, message, risk_result)
        service.storage.save_chat_message(doc_id, "user", message)
        service.storage.save_chat_message(doc_id, "assistant", response)
        return jsonify({"message": response})

    @app.get("/api/documents/<doc_id>/assistant/chat")
    def assistant_chat_get(doc_id: str):
        history = service.storage.get_chat_history(doc_id)
        return jsonify(history)

    # ── Dataset & Accuracy Analytics ───────────────────────────

    @app.get("/api/dataset/accuracy")
    def dataset_accuracy():
        dataset = service.storage.get_accuracy_dataset()
        
        tp = 0 # True Positives: Model says SUSPECT/BLOCK, Human says REJECTED
        tn = 0 # True Negatives: Model says LOW/WATCH, Human says APPROVED
        fp = 0 # False Positives: Model says SUSPECT/BLOCK, Human says APPROVED
        fn = 0 # False Negatives: Model says LOW/WATCH, Human says REJECTED
        
        reviewed_count = 0
        total_count = len(dataset)
        
        for item in dataset:
            verdict = item.get("manual_verdict")
            pred = item.get("model_state")
            
            if verdict in ("APPROVED", "REJECTED"):
                reviewed_count += 1
                is_human_fraud = (verdict == "REJECTED")
                is_model_fraud = (pred in ("SUSPECT", "BLOCK"))
                
                if is_human_fraud and is_model_fraud:
                    tp += 1
                elif not is_human_fraud and not is_model_fraud:
                    tn += 1
                elif not is_human_fraud and is_model_fraud:
                    fp += 1
                elif is_human_fraud and not is_model_fraud:
                    fn += 1
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return jsonify({
            "total_count": total_count,
            "reviewed_count": reviewed_count,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": precision,
            "recall": recall,
            "accuracy": accuracy,
            "f1_score": f1_score,
            "dataset": dataset
        })

    @app.get("/api/dataset/export/csv")
    def export_dataset_csv():
        import csv
        import io
        from flask import make_response
        
        dataset = service.storage.get_accuracy_dataset()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Headers
        writer.writerow([
            "Document ID", 
            "Created At", 
            "Pipeline State", 
            "Processing Time (ms)", 
            "Model Fraud Score", 
            "Model Verdict State", 
            "Manual Verdict State", 
            "Reviewed By", 
            "Review Notes",
            "Device / Tester",
            "Final Reason Summary"
        ])
        
        for item in dataset:
            created_str = ""
            if item.get("created_at"):
                created_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item["created_at"]))
            
            writer.writerow([
                item.get("doc_id", ""),
                created_str,
                item.get("pipeline_state", ""),
                item.get("processing_time_ms", ""),
                item.get("fraud_score", ""),
                item.get("model_state", ""),
                item.get("manual_verdict", ""),
                item.get("reviewed_by", ""),
                item.get("review_notes", ""),
                item.get("device_name", ""),
                item.get("final_reason_summary", "")
            ])
            
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=fraudsniffer_dataset.csv"
        response.headers["Content-type"] = "text/csv"
        return response

    @app.get("/api/dataset/export/zip")
    def export_dataset_zip():
        import io
        import zipfile
        import csv
        from flask import send_file
        
        dataset = service.storage.get_accuracy_dataset()
        
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # 1. Add SQLite database
            db_path = Path(service.storage.db_path).resolve()
            if db_path.exists():
                zip_file.write(db_path, arcname=db_path.name)
                
            # 2. Add CSV dataset log
            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            writer.writerow([
                "Document ID", "Created At", "Pipeline State", "Processing Time (ms)",
                "Model Fraud Score", "Model Verdict State", "Manual Verdict State",
                "Reviewed By", "Review Notes", "Device / Tester", "Final Reason Summary"
            ])
            for item in dataset:
                created_str = ""
                if item.get("created_at"):
                    created_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item["created_at"]))
                writer.writerow([
                    item.get("doc_id", ""),
                    created_str,
                    item.get("pipeline_state", ""),
                    item.get("processing_time_ms", ""),
                    item.get("fraud_score", ""),
                    item.get("model_state", ""),
                    item.get("manual_verdict", ""),
                    item.get("reviewed_by", ""),
                    item.get("review_notes", ""),
                    item.get("device_name", ""),
                    item.get("final_reason_summary", "")
                ])
            zip_file.writestr("dataset.csv", csv_buffer.getvalue())
            
            # 3. Add all original and annotated files
            for item in dataset:
                doc_id = item.get("doc_id")
                paths = service.get_paths(doc_id)
                if paths:
                    if paths.get("original_path"):
                        orig_path = Path(paths["original_path"]).resolve()
                        if orig_path.exists():
                            zip_file.write(orig_path, arcname=f"documents/originals/{orig_path.name}")
                    if paths.get("annotated_path"):
                        ann_path = Path(paths["annotated_path"]).resolve()
                        if ann_path.exists():
                            zip_file.write(ann_path, arcname=f"documents/annotated/{ann_path.name}")
                            
        zip_buffer.seek(0)
        return send_file(
            zip_buffer,
            mimetype="application/zip",
            as_attachment=True,
            download_name="fraudsniffer_full_dataset.zip"
        )

    # ── Review ─────────────────────────────────────────────────

    @app.post("/api/reviews/<doc_id>")
    def save_review(doc_id: str):
        body = request.get_json(silent=True) or {}
        reviewed_by = (body.get("reviewed_by") or "").strip()
        manual_verdict = (body.get("manual_verdict") or "").strip().upper()
        if not reviewed_by:
            return jsonify({"error": "reviewed_by is required"}), 400
        if manual_verdict not in ("APPROVED", "REJECTED", "ESCALATE"):
            return jsonify({"error": "manual_verdict must be APPROVED, REJECTED, or ESCALATE"}), 400
        review = service.save_review(
            doc_id,
            body.get("review_notes"),
            reviewed_by,
            manual_verdict,
        )
        return jsonify(review)

    # ── Webhook Test ───────────────────────────────────────────

    @app.post("/api/webhook/test")
    def test_webhook():
        body = request.get_json(silent=True) or {"event": "fraudsniffer_webhook_test"}
        return jsonify(service.test_webhook(body))

    # ── File Serving ───────────────────────────────────────────

    @app.get("/api/documents/<doc_id>/original")
    def original(doc_id: str):
        paths = service.get_paths(doc_id)
        if not paths or not paths.get("original_path"):
            return jsonify({"error": "document not found"}), 404
        file_path = Path(paths["original_path"]).resolve()
        logger.info(f"REQUESTED ORIGINAL PATH: {file_path}")
        logger.info(f"FILE EXISTS: {file_path.exists()}")
        if not file_path.exists():
            return jsonify({"error": "original file not found on disk", "path": str(file_path)}), 404
        return send_file(file_path)

    @app.get("/api/documents/<doc_id>/page/<int:page_number>")
    def rendered_page(doc_id: str, page_number: int):
        if page_number < 1:
            return jsonify({"error": "page_number must be >= 1"}), 400
        paths = service.get_paths(doc_id)
        if not paths or not paths.get("original_path"):
            return jsonify({"error": "document not found"}), 404
        file_path = Path(paths["original_path"]).resolve()
        if not file_path.exists():
            return jsonify({"error": "original file not found on disk", "path": str(file_path)}), 404

        try:
            if file_path.suffix.lower() == ".pdf":
                import fitz  # type: ignore

                doc = fitz.open(str(file_path))
                try:
                    if doc.is_encrypted:
                        raise ValueError("PDF is encrypted or password-protected.")
                    if page_number > len(doc):
                        raise ValueError(f"Page {page_number} is outside the document page range.")
                    pix = doc[page_number - 1].get_pixmap(dpi=150, alpha=False)
                    buffer = io.BytesIO(pix.tobytes("png"))
                    buffer.seek(0)
                    return send_file(buffer, mimetype="image/png", download_name=f"{doc_id}_page_{page_number}.png")
                finally:
                    doc.close()

            from PIL import Image  # type: ignore

            if page_number != 1:
                raise ValueError("Image documents only have one preview page.")
            buffer = io.BytesIO()
            with Image.open(file_path) as image:
                image.convert("RGB").save(buffer, "PNG")
            buffer.seek(0)
            return send_file(buffer, mimetype="image/png", download_name=f"{doc_id}_page_1.png")
        except Exception as exc:
            logger.warning("Could not render document page for %s page %s: %s", doc_id, page_number, exc)
            return send_file(
                _placeholder_png(str(exc)),
                mimetype="image/png",
                download_name=f"{doc_id}_page_{page_number}_placeholder.png",
            )

    @app.get("/api/documents/<doc_id>/annotated")
    def annotated(doc_id: str):
        paths = service.get_paths(doc_id)
        if not paths or not paths.get("annotated_path"):
            return jsonify({"error": "annotated artifact not found"}), 404
        file_path = Path(paths["annotated_path"]).resolve()
        logger.info(f"ANNOTATED FILE PATH: {file_path}")
        logger.info(f"EXISTS: {file_path.exists()}")
        if not file_path.exists():
            return jsonify({"error": "annotated file not found on disk", "path": str(file_path)}), 404
        return send_file(file_path)

    @app.get("/api/documents/<doc_id>/seal/extracted")
    def extracted_seal(doc_id: str):
        paths = service.get_paths(doc_id)
        if not paths or not paths.get("extracted_seal_path"):
            return jsonify({"error": "extracted seal not found"}), 404
        file_path = Path(paths["extracted_seal_path"]).resolve()
        if not file_path.exists():
            return jsonify({"error": "extracted seal file not found on disk", "path": str(file_path)}), 404
        return send_file(file_path)

    @app.get("/api/documents/<doc_id>/seal/reference")
    def reference_seal(doc_id: str):
        paths = service.get_paths(doc_id)
        if not paths or not paths.get("reference_seal_path"):
            return jsonify({"error": "reference seal not found"}), 404
        file_path = Path(paths["reference_seal_path"]).resolve()
        if not file_path.exists():
            return jsonify({"error": "reference seal file not found on disk", "path": str(file_path)}), 404
        return send_file(file_path)

    @app.get("/api/documents/<doc_id>/seal/comparison")
    def comparison_seal(doc_id: str):
        paths = service.get_paths(doc_id)
        if not paths or not paths.get("extracted_seal_path"):
            return jsonify({"error": "extracted seal path not found"}), 404
        extracted_path = Path(paths["extracted_seal_path"]).resolve()
        # Comparison file is in the same directory as extracted seal
        comparison_path = extracted_path.parent / f"{extracted_path.stem.replace('_seal', '')}_comparison.png"
        if not comparison_path.exists():
            return jsonify({"error": "comparison overlay file not found on disk", "path": str(comparison_path)}), 404
        return send_file(comparison_path)

    @app.get("/api/documents/<doc_id>/audit_trail")
    def audit_trail(doc_id: str):
        risk = service.get_risk(doc_id)
        if not risk:
            return jsonify({"error": "document not found"}), 404
        return jsonify({
            "pqc_audit_trail": risk.get("pqc_audit_trail", []),
            "pqc_integrity_ok": risk.get("pqc_integrity_ok", False),
            "pqc_integrity_message": risk.get("pqc_integrity_message", "No audit data found."),
            "verification_result": risk.get("verification_result", {}),
            "verification_stats": risk.get("verification_stats", {}),
        })

    @app.get("/api/documents/<doc_id>/telemetry")
    def document_telemetry(doc_id: str):
        telemetry = service.storage.get_telemetry(doc_id)
        if not telemetry:
            return jsonify({"error": "no telemetry data for this document"}), 404
        # Also include device profile stats
        fp = telemetry.get("canvas_fingerprint", "")
        device_count = service.storage.get_device_submission_count(fp)
        device_docs = service.storage.get_device_doc_ids(fp)
        telemetry["device_total_submissions"] = device_count
        telemetry["device_associated_docs"] = device_docs[:20]
        return jsonify(telemetry)

    @app.get("/api/documents/<doc_id>/forensics")
    def document_forensics(doc_id: str):
        risk = service.get_risk(doc_id)
        if not risk:
            return jsonify({"error": "document not found"}), 404
        return jsonify({
            "doc_id": doc_id,
            "advanced_forensics": risk.get("advanced_forensics") or {},
            "similarity_matches": risk.get("similarity_matches") or [],
            "artifacts": risk.get("artifacts") or {},
        })

    @app.get("/api/documents/<doc_id>/forensics/ela/<int:page_number>")
    def ela_heatmap(doc_id: str, page_number: int):
        if page_number < 1:
            return jsonify({"error": "page_number must be >= 1"}), 400
        risk = service.storage.get_risk(doc_id)
        if not risk:
            return jsonify({"error": "document not found"}), 404

        pages = (
            (risk.get("advanced_forensics") or {})
            .get("visual", {})
            .get("ela", {})
            .get("pages", [])
        )
        artifact_path = None
        for page in pages:
            if int(page.get("page") or 0) == page_number and page.get("artifact_path"):
                artifact_path = Path(page["artifact_path"]).resolve()
                break
        if artifact_path is None:
            artifact_path = (service.forensics_dir / f"{doc_id}_ela_page_{page_number}.png").resolve()
        if not artifact_path.exists():
            return jsonify({"error": "ELA heatmap not found", "path": str(artifact_path)}), 404
        return send_file(artifact_path)

    # ── Health & Diagnostics ───────────────────────────────────

    @app.get("/metrics")
    def metrics():
        return "fraudsniffer_up 1\n", 200, {"Content-Type": "text/plain"}

    @app.get("/api/health")
    def health():
        dep_config = [
            {
                "label": "PyMuPDF",
                "module": "fitz",
                "features": ["PDF text extraction (primary)", "PDF page rendering"],
                "fallback": "pypdf + Tesseract fallback for PDF extraction",
            },
            {
                "label": "pytesseract",
                "module": "pytesseract",
                "features": ["OCR on images", "OCR on scanned PDFs"],
                "fallback": "Text extraction limited to embedded PDF text",
            },
            {
                "label": "pypdf",
                "module": "pypdf",
                "features": ["PDF text extraction (fallback)", "PDF metadata analysis"],
                "fallback": "PDF extraction available via PyMuPDF; Tesseract OCR as last resort",
            },
            {
                "label": "Pillow",
                "module": "PIL",
                "pip_name": "Pillow",
                "features": ["Image processing", "Seal analysis", "Annotated document generation"],
                "fallback": "Seal verification unavailable; annotations saved as text",
            },
            {
                "label": "imagehash",
                "module": "imagehash",
                "features": ["Seal perceptual hash (pHash)", "Image similarity checks"],
                "fallback": "Built-in average-hash fallback active — reduced accuracy",
            },
            {
                "label": "Flask",
                "module": "flask",
                "features": ["Web dashboard", "REST API"],
                "fallback": None,
            },
        ]
        results = {}
        missing_packages = []
        all_healthy = True
        for cfg in dep_config:
            label = cfg["label"]
            module_name = cfg["module"]
            pip_name = cfg.get("pip_name", label.lower() if label != "PyMuPDF" else "PyMuPDF")
            try:
                mod = __import__(module_name)
                if module_name == "flask":
                    import importlib.metadata
                    version = importlib.metadata.version("flask")
                else:
                    version = getattr(mod, "__version__", getattr(mod, "VERSION", None))
                results[label] = {
                    "status": "available",
                    "version": str(version) if version else "installed",
                    "features": cfg["features"],
                    "fallback": None,
                    "error": None,
                    "error_type": None,
                    "install_hint": None,
                }
            except ImportError as exc:
                all_healthy = False
                missing_packages.append(pip_name)
                results[label] = {
                    "status": "missing",
                    "version": None,
                    "features": cfg["features"],
                    "fallback": cfg.get("fallback"),
                    "error": str(exc),
                    "error_type": "missing_package",
                    "install_hint": f"pip install {pip_name}",
                }
            except Exception as exc:
                all_healthy = False
                missing_packages.append(pip_name)
                error_type = "dependency_conflict" if "version" in str(exc).lower() else "import_error"
                results[label] = {
                    "status": "error",
                    "version": None,
                    "features": cfg["features"],
                    "fallback": cfg.get("fallback"),
                    "error": str(exc),
                    "error_type": error_type,
                    "install_hint": f"pip install --upgrade {pip_name}",
                }
        return jsonify({
            "status": "ok" if all_healthy else "degraded",
            "all_healthy": all_healthy,
            "dependencies": results,
            "pqc_diagnostics": service.pqc_startup_diagnostics,
            "install_command": f"pip install {' '.join(missing_packages)}" if missing_packages else None,
            "data_dir": str(service.root_dir),
            "model_version": service.model_version,
            "db_path": str(service.storage.db_path),
        })

    # ── Debug Trace ────────────────────────────────────────────

    @app.get("/api/documents/<doc_id>/debug")
    def debug_trace(doc_id: str):
        risk_data = service.get_risk(doc_id)
        if not risk_data:
            return jsonify({"error": "document not found"}), 404
        debug_info = {
            "doc_id": doc_id,
            "ocr_text_preview": (risk_data.get("_ocr_text") or "")[:500],
            "extracted_fields": {},
            "missing_fields": [],
            "parse_coverage_score": None,
            "feature_values": {},
            "triggered_rules": risk_data.get("risk_decision_reason_codes", []),
            "suppressed_rules": [],
            "confidence_breakdown": risk_data.get("confidence_breakdown", {}),
            "warnings": risk_data.get("warnings", risk_data.get("ocr_warnings", [])),
            "final_score": risk_data.get("fraud_score"),
            "state": risk_data.get("state"),
        }
        feature_status = risk_data.get("feature_status", {})
        for fname, fstatus in feature_status.items():
            if fstatus == "REAL" or fstatus == "DERIVED":
                debug_info["extracted_fields"][fname] = fstatus
            elif fstatus == "UNAVAILABLE":
                debug_info["missing_fields"].append(fname)
            debug_info["feature_values"][fname] = fstatus
        debug_info["parse_coverage_score"] = risk_data.get("confidence_breakdown", {}).get("parse_coverage_score")
        return jsonify(debug_info)

    # ── Graph Intelligence API ─────────────────────────────────

    @app.get("/api/graph/network/<doc_id>")
    def graph_network(doc_id: str):
        """Get the fraud network graph for a specific document in Cytoscape.js format."""
        if not hasattr(service, 'graph_intel') or not service.graph_intel.available:
            return jsonify({"error": "Graph intelligence not available", "available": False}), 503
        max_hops = request.args.get("max_hops", 3, type=int)
        network = service.graph_intel.get_network_for_document(doc_id, max_hops=max_hops)
        return jsonify(network)

    @app.get("/api/graph/full")
    def graph_full():
        """Get the complete fraud network graph (limited) for overview visualization."""
        if not hasattr(service, 'graph_intel') or not service.graph_intel.available:
            return jsonify({"error": "Graph intelligence not available", "available": False}), 503
        limit = request.args.get("limit", 200, type=int)
        graph = service.graph_intel.get_full_graph(limit=limit)
        return jsonify(graph)

    @app.get("/api/graph/rings")
    def graph_rings():
        """Detect and list all fraud rings in the graph."""
        if not hasattr(service, 'graph_intel') or not service.graph_intel.available:
            return jsonify({"error": "Graph intelligence not available", "available": False}), 503
        rings = service.graph_intel.detect_fraud_rings()
        return jsonify({"rings": rings, "ring_count": len(rings)})

    @app.get("/api/graph/ring/<ring_id>")
    def graph_ring_detail(ring_id: str):
        """Get detailed information about a specific fraud ring."""
        if not hasattr(service, 'graph_intel') or not service.graph_intel.available:
            return jsonify({"error": "Graph intelligence not available", "available": False}), 503
        rings = service.graph_intel.detect_fraud_rings()
        ring = next((r for r in rings if r.get("ring_id") == ring_id), None)
        if not ring:
            return jsonify({"error": "ring not found"}), 404
        return jsonify(ring)

    @app.get("/api/graph/stats")
    def graph_stats():
        """Get graph intelligence statistics."""
        if not hasattr(service, 'graph_intel') or not service.graph_intel.available:
            return jsonify({"available": False, "message": "Graph intelligence not available"})
        stats = service.graph_intel.get_graph_stats()
        stats["available"] = True
        return jsonify(stats)

    @app.post("/api/graph/propagate/<doc_id>")
    def graph_propagate(doc_id: str):
        """Trigger risk propagation from a specific document through the graph."""
        if not hasattr(service, 'graph_intel') or not service.graph_intel.available:
            return jsonify({"error": "Graph intelligence not available", "available": False}), 503
        result = service.graph_intel.calculate_risk_propagation(doc_id)
        return jsonify(result)

    @app.post("/api/graph/sync")
    def graph_sync():
        """Sync all existing SQLite cases to Neo4j graph (for initial population)."""
        if not hasattr(service, 'graph_intel') or not service.graph_intel.available:
            return jsonify({"error": "Graph intelligence not available", "available": False}), 503
        import json as _json
        synced = 0
        errors = 0
        with service.storage._connect() as conn:
            rows = conn.execute(
                "SELECT doc_id, risk_json, metadata_json FROM documents WHERE risk_json IS NOT NULL"
            ).fetchall()
        for row in rows:
            try:
                risk_data = _json.loads(row["risk_json"]) if row["risk_json"] else {}
                metadata = _json.loads(row["metadata_json"]) if row["metadata_json"] else {}
                telemetry = service.storage.get_telemetry(row["doc_id"]) or {}
                service.graph_intel.ingest_case(
                    doc_id=row["doc_id"],
                    risk_data=risk_data,
                    telemetry_data=telemetry,
                    metadata=metadata,
                )
                synced += 1
            except Exception as e:
                logger.warning(f"Graph sync error for {row['doc_id']}: {e}")
                errors += 1
        return jsonify({"synced": synced, "errors": errors, "total": len(rows)})

    return app

