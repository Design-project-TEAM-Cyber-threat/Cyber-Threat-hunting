"""Django settings for the threat-hunting prototype (SQLite, demo-grade)."""
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent          # backend/
PROJECT_ROOT = BASE_DIR.parent                             # threat-hunter/ (contains the ml package)
sys.path.insert(0, str(PROJECT_ROOT))

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-only-not-for-production")
DEBUG = os.environ.get("DJANGO_DEBUG", "1") == "1"
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "corsheaders",
    "rest_framework",
    "alerts",
]
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
]
ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
TIME_ZONE = "UTC"

# Vite dev server for the later React dashboard
CORS_ALLOWED_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_AUTHENTICATION_CLASSES": [],      # demo only: no auth. Add auth before any real deployment.
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
}

# Trained models produced by Steps 3-5
ML_ARTIFACTS_DIR = PROJECT_ROOT / "ml" / "artifacts"
