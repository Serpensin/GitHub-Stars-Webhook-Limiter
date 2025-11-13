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
APP_VERSION = "2.0.3"

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

# Cleanup thresholds (in days)
CLEANUP_INACTIVE_REPOSITORIES_DAYS = 360
CLEANUP_INACTIVE_WEBHOOKS_DAYS = 360
CLEANUP_INACTIVE_API_KEYS_DAYS = 360

# API Permissions Configuration
# This centralized configuration ensures consistency across all components
PERMISSIONS = [
    {
        "name": "generate-secret",
        "friendly_name": "Generate Secret",
        "bit": 0,
        "value": 1,
        "description": "Allows generating webhook secrets for repositories",
        "endpoints": ["/api/generate-secret"],
    },
    {
        "name": "repositories-add",
        "friendly_name": "Add Repository",
        "bit": 1,
        "value": 2,
        "description": "Allows adding new repositories to the limiter",
        "endpoints": ["/api/repositories"],  # POST method # NOSONAR
    },
    {
        "name": "repositories-verify",
        "friendly_name": "Verify Repository",
        "bit": 2,
        "value": 4,
        "description": "Allows verifying repository webhook configurations",
        "endpoints": ["/api/repositories/verify"],
    },
    {
        "name": "repositories-update",
        "friendly_name": "Update Repository",
        "bit": 3,
        "value": 8,
        "description": "Allows updating repository settings and configurations",
        "endpoints": ["/api/repositories"],  # PATCH method
    },
    {
        "name": "repositories-delete",
        "friendly_name": "Delete Repository",
        "bit": 4,
        "value": 16,
        "description": "Allows deleting repositories from the limiter",
        "endpoints": ["/api/repositories"],  # DELETE method
    },
    {
        "name": "events-list",
        "friendly_name": "List Events",
        "bit": 5,
        "value": 32,
        "description": "Allows listing available event types",
        "endpoints": ["/api/events"],
    },
    {
        "name": "permissions-list",
        "friendly_name": "List Permissions",
        "bit": 6,
        "value": 64,
        "description": "Allows listing available permissions",
        "endpoints": ["/api/permissions"],
    },
    {
        "name": "permissions-calculate",
        "friendly_name": "Calculate Permissions",
        "bit": 7,
        "value": 128,
        "description": "Allows calculating permission bitmaps from permission lists",
        "endpoints": ["/api/permissions/calculate"],
    },
    {
        "name": "permissions-decode",
        "friendly_name": "Decode Permissions",
        "bit": 8,
        "value": 256,
        "description": "Allows decoding permission bitmaps to permission lists",
        "endpoints": ["/api/permissions/decode"],
    },
    {
        "name": "stats",
        "friendly_name": "View Statistics",
        "bit": 9,
        "value": 512,
        "description": "Allows viewing system statistics and analytics",
        "endpoints": ["/api/stats"],
    },
]

# Derive permission key list for BitmapHandler (order matters!)
PERMISSION_KEYS = [perm["name"] for perm in PERMISSIONS]

# Calculate maximum permission value
MAX_PERMISSION_VALUE = (1 << len(PERMISSIONS)) - 1

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
    ],
}
