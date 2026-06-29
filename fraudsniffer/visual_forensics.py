from __future__ import annotations

import io
from pathlib import Path
from statistics import mean, median
from typing import Any, Dict, List

try:
    from PIL import Image, ImageChops, ImageEnhance
except Exception:  # pragma: no cover - optional dependency availability
    Image = None  # type: ignore
    ImageChops = None  # type: ignore
    ImageEnhance = None  # type: ignore


ELA_TRIGGER_SCORE = 0.25


def _pixel_values(image: Any) -> list[Any]:
    getter = getattr(image, "get_flattened_data", None)
    if getter:
        return list(getter())
    return list(image.getdata())


def _render_pages(document_path: Path, max_pages: int) -> List[Any]:
    if Image is None:
        return []

    suffix = document_path.suffix.lower()
    if suffix == ".pdf":
        try:
            import fitz  # type: ignore

            pages = []
            doc = fitz.open(str(document_path))
            for index in range(min(len(doc), max_pages)):
                pix = doc[index].get_pixmap(dpi=150, alpha=False)
                page = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
                pages.append(page)
            doc.close()
            return pages
        except Exception:
            return []

    try:
        return [Image.open(document_path).convert("RGB")]
    except Exception:
        return []


def _ela_for_image(image: Any, output_path: Path) -> Dict[str, Any]:
    """Run JPEG error level analysis on one rendered page/image."""
    recompressed = io.BytesIO()
    image.save(recompressed, "JPEG", quality=90)
    recompressed.seek(0)
    jpeg = Image.open(recompressed).convert("RGB")
    diff = ImageChops.difference(image, jpeg)
    gray = diff.convert("L")
    values = _pixel_values(gray)
    if not values:
        return {"score": 0.0, "mean_error": 0.0, "max_error": 0}

    mean_error = mean(values)
    max_error = max(values)
    bright_threshold = max(18, int(mean_error + 24))
    hot_pixels = sum(1 for value in values if value >= bright_threshold)
    hot_ratio = hot_pixels / len(values)
    tile_means = []
    tile_size = 32
    width, height = image.size
    for left in range(0, width, tile_size):
        for top in range(0, height, tile_size):
            crop = gray.crop((left, top, min(left + tile_size, width), min(top + tile_size, height)))
            tile_values = _pixel_values(crop)
            if tile_values:
                tile_means.append(mean(tile_values))
    median_tile_error = median(tile_means) if tile_means else 0.0
    max_tile_error = max(tile_means) if tile_means else 0.0
    tile_outlier = max(0.0, max_tile_error - median_tile_error)

    # ELA is strongest when a small local region is much noisier than the rest.
    score = min(
        1.0,
        (mean_error / 45.0) * 0.20
        + (max_error / 255.0) * 0.25
        + hot_ratio * 3.0
        + (tile_outlier / 38.0) * 0.55,
    )

    enhanced = ImageEnhance.Brightness(diff).enhance(12)
    heatmap = Image.new("RGB", image.size, (245, 247, 250))
    heat_pixels = heatmap.load()
    diff_pixels = enhanced.convert("L").load()
    for x in range(width):
        for y in range(height):
            value = diff_pixels[x, y]
            if value >= 80:
                heat_pixels[x, y] = (220, 30, 30)
            elif value >= 35:
                heat_pixels[x, y] = (245, 158, 11)
            else:
                g = min(240, 70 + value)
                heat_pixels[x, y] = (g, g, g)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    heatmap.save(output_path)

    return {
        "score": round(float(score), 4),
        "mean_error": round(float(mean_error), 3),
        "max_error": int(max_error),
        "hot_pixel_ratio": round(float(hot_ratio), 5),
        "max_tile_error": round(float(max_tile_error), 3),
        "median_tile_error": round(float(median_tile_error), 3),
    }


def analyze_visual_forensics(
    document_path: Path | str,
    output_dir: Path | str,
    doc_id: str,
    max_pages: int = 3,
    is_scanned: bool = False,
) -> Dict[str, Any]:
    """Generate ELA heatmaps and return a compact forensic summary."""
    path = Path(document_path)
    out_dir = Path(output_dir)
    if Image is None or ImageChops is None or ImageEnhance is None:
        return {
            "ela": {
                "status": "UNAVAILABLE",
                "triggered": False,
                "max_score": 0.0,
                "detail": "Pillow is unavailable, so ELA could not run.",
                "pages": [],
            }
        }

    rendered_pages = _render_pages(path, max_pages=max_pages)
    if not rendered_pages:
        return {
            "ela": {
                "status": "UNAVAILABLE",
                "triggered": False,
                "max_score": 0.0,
                "detail": "Document could not be rendered for ELA.",
                "pages": [],
            }
        }

    pages = []
    for index, image in enumerate(rendered_pages, start=1):
        artifact_path = out_dir / f"{doc_id}_ela_page_{index}.png"
        metrics = _ela_for_image(image, artifact_path)
        pages.append(
            {
                "page": index,
                "artifact_path": str(artifact_path.resolve()),
                **metrics,
            }
        )

    max_score = max((page["score"] for page in pages), default=0.0)
    effective_threshold = ELA_TRIGGER_SCORE + (0.15 if is_scanned else 0.0)
    triggered = max_score >= effective_threshold
    detail = (
        f"ELA max score {max_score:.3f} across {len(pages)} rendered page(s)."
        if pages
        else "No pages were available for ELA."
    )
    return {
        "ela": {
            "status": "REAL",
            "triggered": triggered,
            "max_score": round(float(max_score), 4),
            "threshold": effective_threshold,
            "detail": detail,
            "pages": pages,
        }
    }
