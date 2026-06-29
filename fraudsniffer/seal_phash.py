from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .models import FeatureStatus, SealEvidence

try:
    from PIL import Image, ImageChops, ImageDraw
except Exception:  # pragma: no cover - import availability depends on env
    Image = None  # type: ignore
    ImageChops = None  # type: ignore
    ImageDraw = None  # type: ignore


def ensure_reference_seal(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or Image is None:
        return path
    image = Image.new("RGBA", (180, 180), (255, 255, 255, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((12, 12, 168, 168), outline=(10, 80, 180, 255), width=8)
    draw.ellipse((36, 36, 144, 144), outline=(10, 80, 180, 255), width=3)
    draw.text((48, 76), "CANARA", fill=(10, 80, 180, 255))
    draw.text((58, 96), "BANK", fill=(10, 80, 180, 255))
    image.convert("RGB").save(path)
    return path


def _fallback_hash(image: Any) -> int:
    small = image.convert("L").resize((8, 8))
    pixels = list(small.getdata())
    avg = sum(pixels) / len(pixels)
    bits = 0
    for index, value in enumerate(pixels):
        if value >= avg:
            bits |= 1 << index
    return bits


def _hash_image(image: Any) -> Any:
    try:
        import imagehash  # type: ignore

        return imagehash.phash(image.convert("L"))
    except Exception:
        return _fallback_hash(image)


def _hash_distance(left: Any, right: Any) -> int:
    left_hash = _hash_image(left)
    right_hash = _hash_image(right)
    try:
        return int(left_hash - right_hash)
    except TypeError:
        return int((left_hash ^ right_hash).bit_count())


def _bbox_from_metadata(metadata: Dict[str, Any]) -> Optional[Tuple[int, int, int, int]]:
    bbox = metadata.get("seal_bbox")
    if not bbox or len(bbox) != 4:
        return None
    try:
        x1, y1, x2, y2 = [int(v) for v in bbox]
    except (TypeError, ValueError):
        return None
    if x2 <= x1 or y2 <= y1:
        return None
    return x1, y1, x2, y2


def _find_colored_stamp_bbox(image: Any) -> Optional[Tuple[int, int, int, int]]:
    """Scan the image for typical colored ink stamps (blue, violet, red)
    and return the bounding box of the highest density stamp region.
    """
    if image is None:
        return None
    
    # Resize image to speed up scanning
    w, h = image.size
    scale = 4
    small = image.resize((w // scale, h // scale))
    pixels = small.load()
    
    match_pixels = []
    # Stamp color thresholds (in RGB)
    for x in range(small.size[0]):
        for y in range(small.size[1]):
            r, g, b = pixels[x, y][:3]
            # Detect blue/purple ink (e.g. Canara Bank stamp)
            is_blue_ink = (b > r + 15) and (b > g + 15) and (b > 60)
            # Detect red/crimson ink
            is_red_ink = (r > g + 30) and (r > b + 30) and (r > 80)
            
            if is_blue_ink or is_red_ink:
                match_pixels.append((x * scale, y * scale))
                
    if len(match_pixels) < 100:  # Too few matching pixels, no stamp
        return None
        
    # Cluster matching pixels to find the bounding box
    # For simplicity, filter outliers and find min/max coordinates
    xs = sorted([p[0] for p in match_pixels])
    ys = sorted([p[1] for p in match_pixels])
    
    # Discard top/bottom 5% to avoid noise outliers
    trim_x = int(len(xs) * 0.05)
    trim_y = int(len(ys) * 0.05)
    
    xs_clean = xs[trim_x : len(xs) - trim_x] if len(xs) > 10 else xs
    ys_clean = ys[trim_y : len(ys) - trim_y] if len(ys) > 10 else ys
    
    if not xs_clean or not ys_clean:
        return None
        
    x1, x2 = xs_clean[0], xs_clean[-1]
    y1, y2 = ys_clean[0], ys_clean[-1]
    
    # Validate dimensions: must be a reasonable stamp size
    stamp_w = x2 - x1
    stamp_h = y2 - y1
    if 40 <= stamp_w <= 350 and 40 <= stamp_h <= 350:
        # Pad the box slightly
        pad = 15
        return (
            max(0, x1 - pad),
            max(0, y1 - pad),
            min(w, x2 + pad),
            min(h, y2 + pad)
        )
    return None


def _expand_bbox(
    bbox: Tuple[int, int, int, int],
    image_size: Tuple[int, int],
    pad: int = 20,
    min_width: int = 0,
    min_height: int = 0,
) -> Tuple[int, int, int, int]:
    width, height = image_size
    x1, y1, x2, y2 = bbox
    x1 -= pad
    y1 -= pad
    x2 += pad
    y2 += pad

    box_w = x2 - x1
    box_h = y2 - y1
    if min_width and box_w < min_width:
        extra = (min_width - box_w) // 2
        x1 -= extra
        x2 += extra
    if min_height and box_h < min_height:
        extra = (min_height - box_h) // 2
        y1 -= extra
        y2 += extra

    return (
        max(0, int(x1)),
        max(0, int(y1)),
        min(width, int(x2)),
        min(height, int(y2)),
    )


def _is_visually_blank(image: Any) -> bool:
    """Return True for near-empty white/flat crops."""
    gray = image.convert("L").resize((80, 80))
    extrema = gray.getextrema()
    if not extrema:
        return True
    low, high = extrema
    if high - low < 8:
        return True
    pixels = list(gray.getdata())
    dark_or_colored = sum(1 for value in pixels if value < 245)
    return (dark_or_colored / max(len(pixels), 1)) < 0.003


def _fitz_rect_to_pixels(rect: Any, dpi: int, image_size: Tuple[int, int]) -> Tuple[int, int, int, int]:
    scale = dpi / 72.0
    bbox = (
        int(rect.x0 * scale),
        int(rect.y0 * scale),
        int(rect.x1 * scale),
        int(rect.y1 * scale),
    )
    return _expand_bbox(bbox, image_size, pad=24, min_width=180, min_height=120)


def _find_seal_text_bbox(page: Any, dpi: int, image_size: Tuple[int, int]) -> Optional[Tuple[int, int, int, int]]:
    """Locate textual seal placeholders such as '[Company Seal]' in generated PDFs."""
    for needle in ("[Company Seal]", "Company Seal", "Seal", "Stamp"):
        try:
            rects = page.search_for(needle)
        except Exception:
            rects = []
        if rects:
            return _fitz_rect_to_pixels(rects[0], dpi, image_size)

    try:
        words = page.get_text("words")
    except Exception:
        return None
    for word in words:
        text = str(word[4]).strip("[](){}:;,.").lower() if len(word) >= 5 else ""
        if text in {"seal", "stamp"}:
            rect_like = type("_Rect", (), {
                "x0": word[0],
                "y0": word[1],
                "x1": word[2],
                "y1": word[3],
            })()
            return _fitz_rect_to_pixels(rect_like, dpi, image_size)
    return None


def create_seal_comparison_overlay(
    extracted_path: Path | str,
    reference_path: Path | str,
    output_path: Path | str
) -> bool:
    """Create a premium visual overlay comparing the extracted seal and the reference seal,
    highlighting pixel differences.
    """
    if Image is None or ImageChops is None:
        return False
    try:
        ext = Image.open(extracted_path).convert("RGB").resize((150, 150))
        ref = Image.open(reference_path).convert("RGB").resize((150, 150))
        
        # Calculate visual difference map
        diff = ImageChops.difference(ext, ref)
        # Convert diff to heatmap: scale differences
        diff_gray = diff.convert("L")
        heatmap = Image.new("RGB", (150, 150))
        h_pixels = heatmap.load()
        d_pixels = diff_gray.load()
        e_pixels = ext.load()
        
        for x in range(150):
            for y in range(150):
                val = d_pixels[x, y]
                # High difference -> highlight in red, low difference -> show original gray
                if val > 30:
                    h_pixels[x, y] = (220, 30, 30)  # Red alert highlight
                else:
                    g = int(0.299 * e_pixels[x, y][0] + 0.587 * e_pixels[x, y][1] + 0.114 * e_pixels[x, y][2])
                    h_pixels[x, y] = (g, g, g)
        
        # Create a single canvas combining Extracted, Reference, and Highlighted Difference
        canvas = Image.new("RGB", (480, 200), (245, 247, 250))
        draw = ImageDraw.Draw(canvas)
        
        canvas.paste(ext, (15, 35))
        canvas.paste(ref, (165, 35))
        canvas.paste(heatmap, (315, 35))
        
        # Draw labels
        draw.text((15, 12), "EXTRACTED", fill=(60, 66, 82))
        draw.text((165, 12), "REFERENCE", fill=(60, 66, 82))
        draw.text((315, 12), "HIGHLIGHTED DIFF", fill=(220, 30, 30))
        
        # Draw borders
        draw.rectangle((14, 34, 166, 186), outline=(200, 205, 215), width=1)
        draw.rectangle((164, 34, 316, 186), outline=(200, 205, 215), width=1)
        draw.rectangle((314, 34, 466, 186), outline=(220, 200, 200), width=1)
        
        canvas.save(output_path)
        return True
    except Exception:
        return False


def _heuristic_bbox(image: Any) -> Tuple[int, int, int, int]:
    width, height = image.size
    size = max(80, min(width, height) // 4)
    margin = max(12, min(width, height) // 25)
    x2 = width - margin
    y2 = height - margin
    return max(0, x2 - size), max(0, y2 - size), x2, y2


def analyze_seal(
    document_path: Path,
    metadata: Dict[str, Any],
    output_dir: Path,
    reference_path: Path,
    threshold: int = 10,
) -> SealEvidence:
    output_dir.mkdir(parents=True, exist_ok=True)
    reference_path = ensure_reference_seal(reference_path)

    if Image is None:
        return SealEvidence(
            seal_phash_distance=None,
            raw_hamming_distance=None,
            feature_status=FeatureStatus.UNAVAILABLE,
            evidence="Pillow is unavailable, so seal pHash could not run.",
            reference_seal_path=str(reference_path) if reference_path.exists() else None,
        )

    dpi = 150
    rendered_pages: list[tuple[int, Any]] = []
    text_candidates: list[tuple[int, Tuple[int, int, int, int], str]] = []

    try:
        if document_path.suffix.lower() == ".pdf":
            import fitz  # type: ignore
            import io

            doc = fitz.open(str(document_path))
            for index in range(min(len(doc), 3)):
                page = doc[index]
                pix = page.get_pixmap(dpi=dpi, alpha=False)
                image = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
                rendered_pages.append((index + 1, image))
                text_bbox = _find_seal_text_bbox(page, dpi, image.size)
                if text_bbox:
                    text_candidates.append((index + 1, text_bbox, "seal text marker"))
            doc.close()
        else:
            rendered_pages.append((1, Image.open(document_path).convert("RGB")))
    except Exception:
        return SealEvidence(
            seal_phash_distance=None,
            raw_hamming_distance=None,
            feature_status=FeatureStatus.UNAVAILABLE,
            evidence="No seal region could be extracted from this document type.",
            reference_seal_path=str(reference_path) if reference_path.exists() else None,
        )

    if not rendered_pages:
        return SealEvidence(
            seal_phash_distance=None,
            raw_hamming_distance=None,
            feature_status=FeatureStatus.UNAVAILABLE,
            evidence="Document could not be rendered for seal extraction.",
            reference_seal_path=str(reference_path),
        )

    candidates: list[tuple[int, Any, Tuple[int, int, int, int], str]] = []
    metadata_bbox = _bbox_from_metadata(metadata)
    if metadata_bbox:
        page_num, page_image = rendered_pages[0]
        candidates.append((page_num, page_image, metadata_bbox, "metadata-provided seal region"))

    for page_num, page_image in rendered_pages:
        colored_bbox = _find_colored_stamp_bbox(page_image)
        if colored_bbox:
            candidates.append((page_num, page_image, colored_bbox, "colored stamp region"))

    for page_num, text_bbox, source in text_candidates:
        page_image = next((image for pnum, image in rendered_pages if pnum == page_num), None)
        if page_image is not None:
            candidates.append((page_num, page_image, text_bbox, source))

    for page_num, page_image in rendered_pages:
        candidates.append((page_num, page_image, _heuristic_bbox(page_image), "heuristic seal region"))

    selected: Optional[tuple[int, Any, str]] = None
    for page_num, page_image, bbox, source in candidates:
        crop_candidate = page_image.crop(bbox).convert("RGB")
        if not _is_visually_blank(crop_candidate):
            selected = (page_num, crop_candidate, source)
            break

    if selected is None:
        return SealEvidence(
            seal_phash_distance=None,
            raw_hamming_distance=None,
            feature_status=FeatureStatus.UNAVAILABLE,
            evidence="No non-blank seal or seal marker could be extracted from the rendered document.",
            reference_seal_path=str(reference_path),
        )

    page_num, crop, source = selected
    extracted_path = output_dir / f"{document_path.stem}_seal.png"
    crop.save(extracted_path)

    # Determine if reference seal is synthetic (auto-generated)
    is_synthetic_reference = not reference_path.exists() or reference_path.stat().st_size < 5000
    # Re-check after ensure_reference_seal may have created it
    if reference_path.exists() and reference_path.stat().st_size < 5000:
        is_synthetic_reference = True

    try:
        reference = Image.open(reference_path).convert("L")
        raw_distance = _hash_distance(crop.convert("L"), reference)
    except Exception as exc:
        return SealEvidence(
            seal_phash_distance=None,
            raw_hamming_distance=None,
            feature_status=FeatureStatus.UNAVAILABLE,
            evidence=f"Reference seal comparison failed: {exc}",
            extracted_seal_path=str(extracted_path),
            reference_seal_path=str(reference_path),
        )

    normalized = min(raw_distance / 64.0, 1.0)
    
    # Generate visual difference overlay image
    comparison_path = output_dir / f"{document_path.stem}_comparison.png"
    create_seal_comparison_overlay(extracted_path, reference_path, comparison_path)

    # Mark low-confidence seal comparisons: heuristic extraction or synthetic reference
    is_heuristic = "heuristic" in source.lower()
    if is_heuristic or is_synthetic_reference:
        seal_status = FeatureStatus.DERIVED
    else:
        seal_status = FeatureStatus.REAL

    evidence_parts = [f"Extracted {source} on page {page_num}"]
    evidence_parts.append(f"Uploaded seal differs from reference seal by perceptual hash distance of {raw_distance}")
    if is_synthetic_reference:
        evidence_parts.append("synthetic_reference")
    if is_heuristic:
        evidence_parts.append("heuristic_extraction")

    return SealEvidence(
        seal_phash_distance=round(normalized, 3),
        raw_hamming_distance=raw_distance,
        feature_status=seal_status,
        evidence=". ".join(evidence_parts) + ".",
        extracted_seal_path=str(extracted_path),
        reference_seal_path=str(reference_path),
    )


def create_annotated_artifact(
    document_path: Path,
    output_path: Path,
    metadata: Dict[str, Any],
    reasons: list[str],
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if Image is None:
        output_path.write_text("\n".join(reasons), encoding="utf-8")
        return output_path

    try:
        if document_path.suffix.lower() == ".pdf":
            import fitz  # type: ignore
            import io
            doc = fitz.open(str(document_path))
            page = doc[0]
            pix = page.get_pixmap(dpi=150)
            img_bytes = pix.tobytes("png")
            doc.close()
            image = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        else:
            image = Image.open(document_path).convert("RGB")
    except Exception:
        image = Image.new("RGB", (900, 600), "white")

    draw = ImageDraw.Draw(image)
    bbox = _bbox_from_metadata(metadata) or _find_colored_stamp_bbox(image)
    if bbox:
        draw.rectangle(bbox, outline=(220, 20, 60), width=5)
        draw.text((bbox[0], max(0, bbox[1] - 22)), "Suspicious stamp/seal region", fill=(220, 20, 60))

    y = 18
    for reason in reasons[:6]:
        draw.rectangle((18, y, min(image.size[0] - 18, 760), y + 30), fill=(255, 245, 220))
        draw.text((26, y + 8), reason, fill=(80, 20, 20))
        y += 38

    image.save(output_path)
    return output_path
