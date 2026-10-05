"""PhishGuard: Flask app. Routes receive input, validate it, call the services, render pages.

The app never opens or fetches any submitted URL; it only analyzes text.
"""
import logging
import os
import uuid

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for

from config import Config
from services import history_service, qr_decoder, safe_browsing
from services.risk_scoring import score_url
from services.url_analyzer import analyze_url, validate_url

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("phishguard")

app = Flask(__name__)
app.config.from_object(Config)
os.makedirs(os.path.dirname(app.config["DATABASE_PATH"]), exist_ok=True)


def run_analysis(url: str, save_history: bool) -> dict:
    """Shared pipeline used by BOTH the URL scanner and the QR scanner."""
    features = analyze_url(url)
    risk = score_url(features)
    external = safe_browsing.check_url(
        features["original_url"], app.config["ENABLE_SAFE_BROWSING"], app.config["GOOGLE_SAFE_BROWSING_API_KEY"])
    saved = False
    if save_history:
        try:
            history_service.save_scan(app.config["DATABASE_PATH"], app.config["DOMAIN_HASH_SALT"],
                                      features["registered_domain"], risk["score"], risk["label"],
                                      [r["rule"] for r in risk["rules"]])
            saved = True
        except Exception:  # history is optional; never break a scan because of it
            log.warning("Could not save scan history")
    log.info("Scan done: score=%s label=%s rules=%d", risk["score"], risk["label"], len(risk["rules"]))
    return {"features": features, "risk": risk, "external": external, "saved": saved}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan-url")
def scan_url():
    return render_template("scan_url.html", value="")


@app.route("/analyze-url", methods=["POST"])
def analyze_url_route():
    raw = request.form.get("url", "")
    ok, cleaned, error = validate_url(raw)
    if not ok:
        flash(error, "danger")
        return render_template("scan_url.html", value=raw[:300]), 400
    result = run_analysis(cleaned, request.form.get("save_history") == "on")
    return render_template("result.html", source="url", qr_text=None, **result)


@app.route("/scan-qr")
def scan_qr():
    return render_template("scan_qr.html")


@app.route("/analyze-qr", methods=["POST"])
def analyze_qr_route():
    file = request.files.get("qr_image")
    if not file or not file.filename:
        flash("Please choose an image file first.", "danger")
        return render_template("scan_qr.html"), 400
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in app.config["ALLOWED_EXTENSIONS"]:
        flash("Unsupported file type. Please upload a PNG, JPG, JPEG or WEBP image.", "danger")
        return render_template("scan_qr.html"), 400
    if (file.mimetype or "").lower() not in app.config["ALLOWED_MIME_TYPES"]:
        flash("Unsupported file type (MIME type not allowed).", "danger")
        return render_template("scan_qr.html"), 400
    data = file.read(app.config["MAX_CONTENT_LENGTH"] + 1)
    if len(data) > app.config["MAX_CONTENT_LENGTH"]:
        return render_template("413.html"), 413

    decoded = qr_decoder.decode_qr(data)  # in memory only; the uploaded filename is never used
    if decoded["status"] != "ok":
        flash(decoded["message"], "warning" if decoded["status"] == "no_qr" else "danger")
        return render_template("scan_qr.html"), 200 if decoded["status"] == "no_qr" else 400

    text = decoded["text"]
    ok, cleaned, _ = validate_url(text)
    if not ok:
        return render_template("result.html", source="qr", qr_text=text, features=None, risk=None,
                               external=None, saved=False)
    result = run_analysis(cleaned, request.form.get("save_history") == "on")
    return render_template("result.html", source="qr", qr_text=text, **result)


@app.route("/awareness")
def awareness():
    return render_template("awareness.html")


@app.route("/quiz")
def quiz():
    return render_template("quiz.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/health")
def health():
    return jsonify(status="ok", qr_support=qr_decoder.ZBAR_AVAILABLE)


@app.route("/history")
def history():
    scans = history_service.list_scans(app.config["DATABASE_PATH"])
    return render_template("history.html", scans=scans)


@app.route("/history/delete", methods=["POST"])
def history_delete():
    count = history_service.delete_all(app.config["DATABASE_PATH"])
    flash(f"Deleted {count} saved scan record(s).", "success")
    return redirect(url_for("history"))


@app.errorhandler(400)
def bad_request(_e):
    return render_template("400.html"), 400


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


@app.errorhandler(413)
def too_large(_e):
    return render_template("413.html"), 413


@app.errorhandler(500)
def server_error(_e):
    return render_template("500.html"), 500  # never show stack traces to users


if __name__ == "__main__":
    app.run(debug=False)
