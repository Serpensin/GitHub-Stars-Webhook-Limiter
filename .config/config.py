"""
Central configuration file for GitHub Events Limiter.

This module contains all application-wide constants and configuration values
that are not loaded from environment variables.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Application metadata
APP_NAME = "GitHub_Events_Limiter"
APP_VERSION = "2.0.0"

# Paths
LOG_FOLDER = os.path.join(APP_NAME, "logs")
DB_PATH = os.path.join(APP_NAME, "data.db")

# Logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# Server
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5000

# Gunicorn workers configuration
GUNICORN_WORKERS = 4
GUNICORN_WORKER_CLASS = "gevent"
GUNICORN_WORKER_CONNECTIONS = 100
GUNICORN_MAX_REQUESTS = 1000
GUNICORN_MAX_REQUESTS_JITTER = 50
GUNICORN_TIMEOUT = 30
GUNICORN_KEEPALIVE = 2
GUNICORN_BACKLOG = 2048

# Rate limiting
DEFAULT_RATE_LIMIT = 100
MAX_RATE_LIMIT = 1000

# Database settings
DB_TIMEOUT = 10.0
DB_CACHE_SIZE = -32000  # 32MB cache (negative = KB)
DB_BUSY_TIMEOUT = 10000  # 10 seconds in milliseconds

# Periodic tasks
RATE_LIMIT_CLEANUP_INTERVAL = 60  # seconds

# Placeholder values that should NOT be used in production
INVALID_PLACEHOLDERS = {
    "ENCRYPTION_KEY": [
        "your-encryption-key-here",
        "your-fernet-key-here",
    ],
    "ADMIN_PASSWORD_HASH": [
        "your-argon2-hash-here",
        "your-admin-password-hash-here",
    ],
    "FLASK_SECRET_KEY": [
        "your-flask-secret-key-here",
        "your-secret-key-here",
    ]
}
