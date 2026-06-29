from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .pipeline import FraudSnifferService
from .web_app import create_app

logger = logging.getLogger("fraudsniffer")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FraudSniffer offline-first document fraud MVP")
    parser.add_argument("--storage", default="data/fraudsniffer.db", help="SQLite database path")
    parser.add_argument("--data-dir", default="data", help="Local data directory")
    parser.add_argument("--submit", help="Submit one document and print risk JSON")
    parser.add_argument("--metadata", help="Metadata JSON file for --submit")
    parser.add_argument("--web", action="store_true", help="Start Flask dashboard/API")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind to (e.g. 0.0.0.0 for external access)")
    parser.add_argument("--api-key", default=None, help="Optional X-API-Key value")
    parser.add_argument("--webhook-url", default=None, help="Optional URL for SUSPECT/BLOCK webhook posts")
    return parser.parse_args()


def _check_dependencies() -> None:
    """Log availability of critical dependencies at startup with rich diagnostics."""
    deps = {
        "PyMuPDF (fitz)": "fitz",
        "pytesseract": "pytesseract",
        "pypdf": "pypdf",
        "Pillow": "PIL",
        "imagehash": "imagehash",
    }
    feature_map = {
        "fitz": "PDF text extraction (primary), PDF rendering",
        "pytesseract": "OCR on images and scanned PDFs",
        "pypdf": "PDF text extraction (fallback), PDF metadata",
        "PIL": "Image processing, seal analysis, annotations",
        "imagehash": "Seal perceptual hash verification",
    }
    fallback_map = {
        "pypdf": "PyMuPDF handles PDF extraction; Tesseract OCR as last resort",
        "imagehash": "Built-in average-hash fallback active",
        "fitz": "pypdf + Tesseract fallback for PDF extraction",
        "pytesseract": "Text extraction limited to embedded PDF text",
        "PIL": "Seal verification unavailable; annotations saved as text",
    }
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    import importlib.metadata
    missing = []
    for label, module_name in deps.items():
        try:
            mod = __import__(module_name)
            try:
                pip_name = module_name
                if module_name == "fitz": pip_name = "PyMuPDF"
                elif module_name == "PIL": pip_name = "Pillow"
                version = importlib.metadata.version(pip_name)
            except Exception:
                version = getattr(mod, "__version__", getattr(mod, "VERSION", None))
            version_str = f" ({version})" if version else ""
            logger.info("✓ %s: available%s — %s", label, version_str, feature_map.get(module_name, ""))
        except ImportError:
            missing.append(module_name if module_name != "PIL" else "Pillow")
            fallback = fallback_map.get(module_name)
            fallback_str = f" | Fallback: {fallback}" if fallback else ""
            logger.warning("⚠ %s: MISSING — %s%s", label, feature_map.get(module_name, "some features degraded"), fallback_str)
        except Exception as exc:
            missing.append(module_name)
            logger.warning("⚠ %s: IMPORT ERROR — %s", label, repr(exc))
    if missing:
        logger.warning("  Install missing: pip install %s", " ".join(missing))


def main() -> None:
    args = parse_args()
    service = FraudSnifferService(
        root_dir=args.data_dir,
        db_path=args.storage,
        webhook_url=args.webhook_url,
    )
    # Task 4: Startup dependency health check
    _check_dependencies()

    if args.submit:
        metadata = {}
        if args.metadata:
            metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
        risk = service.process_file(args.submit, metadata)
        print(json.dumps(risk.to_dict(), indent=2))
        return

    if args.web:
        app = create_app(service, api_key=args.api_key)
        app.run(host=args.host, port=args.port, debug=False)
        return

    raise SystemExit("Use --submit or --web")


if __name__ == "__main__":
    main()
