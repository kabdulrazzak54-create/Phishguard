import io

import pytest

import app as app_module


@pytest.fixture
def client(tmp_path):
    app_module.app.config.update(TESTING=True, DATABASE_PATH=str(tmp_path / "t.db"))
    return app_module.app.test_client()


@pytest.mark.parametrize("path", ["/", "/scan-url", "/scan-qr", "/awareness", "/quiz", "/about", "/privacy", "/history"])
def test_pages_ok(client, path):
    assert client.get(path).status_code == 200


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.get_json()["status"] == "ok"


def test_404_page(client):
    assert client.get("/nope").status_code == 404


def test_analyze_url_ok(client):
    r = client.post("/analyze-url", data={"url": "http://192.0.2.1/login"})
    body = r.get_data(as_text=True)
    assert r.status_code == 200 and "SUSPICIOUS" in body and "Why this result?" in body
    assert 'href="http://192.0.2.1' not in body  # scanned URL is never a link


def test_analyze_url_escapes_html(client):
    r = client.post("/analyze-url", data={"url": "https://example.com/<script>alert(1)</script>"})
    assert "<script>alert(1)</script>" not in r.get_data(as_text=True)


def test_analyze_url_invalid(client):
    r = client.post("/analyze-url", data={"url": "javascript:alert(1)"})
    assert r.status_code == 400


def test_qr_rejects_bad_extension(client):
    r = client.post("/analyze-qr", data={"qr_image": (io.BytesIO(b"x"), "evil.exe")},
                    content_type="multipart/form-data")
    assert r.status_code == 400


def test_qr_rejects_bad_mime(client):
    r = client.post("/analyze-qr", data={"qr_image": (io.BytesIO(b"x"), "a.png", "text/html")},
                    content_type="multipart/form-data")
    assert r.status_code == 400


def test_qr_rejects_oversize(client):
    big = io.BytesIO(b"0" * (5 * 1024 * 1024 + 10))
    r = client.post("/analyze-qr", data={"qr_image": (big, "a.png", "image/png")},
                    content_type="multipart/form-data")
    assert r.status_code == 413


def test_history_save_and_delete(client):
    client.post("/analyze-url", data={"url": "https://example.com/login", "save_history": "on"})
    assert "example.com" not in client.get("/history").get_data(as_text=True).replace("example.com/login", "")
    r = client.post("/history/delete", follow_redirects=True)
    assert "Deleted 1" in r.get_data(as_text=True)
