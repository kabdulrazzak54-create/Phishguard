"""QR decoder: reads a QR image IN MEMORY (nothing is written to disk) and returns its text."""
import io
import logging
import uuid
from typing import Any

from PIL import Image, UnidentifiedImageError

try:
    from pyzbar.pyzbar import decode as _zbar_decode
    ZBAR_AVAILABLE = True
except Exception:  # ImportError, or OSError when the ZBar system library is missing
    _zbar_decode = None
    ZBAR_AVAILABLE = False

log = logging.getLogger(__name__)
ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP"}
ZBAR_HELP = ("QR decoding is not available because the ZBar system library is missing. "
             "Install it (Windows: bundled with pyzbar wheels; macOS: 'brew install zbar'; "
             "Ubuntu/Debian: 'sudo apt install libzbar0') and restart the app.")


def decode_qr(data: bytes) -> dict[str, Any]:
    """Decode QR content from image bytes.

    Returns {"status": "ok"|"no_qr"|"invalid_image"|"unsupported"|"unavailable",
             "text": str, "message": str}
    """
    # A random name is used only to refer to this upload in logs; the user's filename is never trusted.
    ref = uuid.uuid4().hex
    if not ZBAR_AVAILABLE:
        return {"status": "unavailable", "text": "", "message": ZBAR_HELP}
    try:
        with Image.open(io.BytesIO(data)) as img:
            if img.format not in ALLOWED_FORMATS:
                return {"status": "unsupported", "text": "",
                        "message": "The file content is not a PNG, JPEG or WEBP image."}
            img.load()
            results = _zbar_decode(img.convert("RGB"))
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, ValueError):
        log.info("QR upload %s could not be read as an image", ref)
        return {"status": "invalid_image", "text": "",
                "message": "That file could not be read as a valid image."}

    qr = [r for r in results if r.type == "QRCODE"]
    if not qr:
        return {"status": "no_qr", "text": "",
                "message": "No QR code was found. Try a clearer, well-lit, cropped image."}
    text = qr[0].data.decode("utf-8", errors="replace")
    return {"status": "ok", "text": text, "message": ""}
