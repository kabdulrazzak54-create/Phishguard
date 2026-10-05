"""Configuration: every setting is read from environment variables (never hardcoded)."""
import os
from dotenv import load_dotenv

load_dotenv()  # reads the local .env file if present (ignored by git)


class Config:
    """Settings used by the Flask app."""

    # Used to sign session cookies / flash messages. Set a long random value in production.
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex()
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB upload limit
    DEBUG = False  # never enable debug in production
    ENABLE_SAFE_BROWSING = os.environ.get("ENABLE_SAFE_BROWSING", "false").lower() == "true"
    GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    DOMAIN_HASH_SALT = os.environ.get("DOMAIN_HASH_SALT", "dev-only-salt-change-me")
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "history.db")
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
    ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "image/webp"}
