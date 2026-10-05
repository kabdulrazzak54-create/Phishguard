import io

import pytest
from PIL import Image

from services import qr_decoder


def png_bytes(color=(255, 255, 255)):
    buf = io.BytesIO()
    Image.new("RGB", (80, 80), color).save(buf, format="PNG")
    return buf.getvalue()


def test_invalid_image_handled():
    r = qr_decoder.decode_qr(b"not an image")
    assert r["status"] in ("invalid_image", "unavailable")


@pytest.mark.skipif(not qr_decoder.ZBAR_AVAILABLE, reason="ZBar not installed")
def test_blank_image_has_no_qr():
    assert qr_decoder.decode_qr(png_bytes())["status"] == "no_qr"


def test_graceful_when_zbar_missing(monkeypatch):
    monkeypatch.setattr(qr_decoder, "ZBAR_AVAILABLE", False)
    r = qr_decoder.decode_qr(png_bytes())
    assert r["status"] == "unavailable" and "ZBar" in r["message"]
