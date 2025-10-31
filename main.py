"""
GitHub Events Limiter

A Flask application that listens for GitHub webhook events (star/watch), validates them,
and sends notifications to Discord webhooks if a user performs an action for the first time.
It uses SQLite for persistence and supports Sentry for error monitoring.

Main features:
- Validates GitHub webhook secrets using HMAC.
- Prevents duplicate notifications for the same user/repo pair.
- Sends Discord notifications for new stars/watches.
- Provides a web UI for managing repositories.
- Stores encrypted secrets for security.
"""

import os
import re
import signal
import sqlite3

# Add .config folder to path for imports
import sys
import time

import requests
import sentry_sdk
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, g

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".config"))

import config  # type: ignore  # config is in .config folder, added to path above

from CustomModules.AuthenticationHandler import AuthenticationHandler
from CustomModules.BitmapHandler import BitmapHandler
from CustomModules.DatabaseHandler import DatabaseHandler
from CustomModules.LogHandler import LogManager
from CustomModules.SecurityHandler import SecurityHandler
from periodic_tasks import PeriodicTaskManager

load_dotenv()

# Initialize logging (logs stored in persistent volume)
os.makedirs(config.LOG_FOLDER, exist_ok=True)
log_manager = LogManager(config.LOG_FOLDER, config.APP_NAME, config.LOG_LEVEL)
logger = log_manager.get_logger(__name__)


def validate_argon2_hash(hash_string: str) -> bool:
    """
    Validate that a string is a valid Argon2 hash.

    Args:
        hash_string: The hash string to validate

    Returns:
        True if valid Argon2 hash, False otherwise
    """
    if not hash_string:
        return False

    # Check format: $argon2id$v=19$m=...,t=...,p=...$...$...
    pattern = r"^\$argon2id?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$"
    if not re.match(pattern, hash_string):
        return False

    # Additional validation: verify it starts with correct prefix
    return hash_string.startswith("$argon2")


# Check for required environment variables and validate them
REQUIRED_ENV_VARS = ["ENCRYPTION_KEY", "ADMIN_PASSWORD_HASH", "FLASK_SECRET_KEY"]
missing_vars = []
invalid_vars = []

for var in REQUIRED_ENV_VARS:
    value = os.environ.get(var)

    if not value:
        missing_vars.append(var)
        continue

    # Check if value is a placeholder
    if value in config.INVALID_PLACEHOLDERS.get(var, []):
        invalid_vars.append((var, "placeholder value detected"))
        continue

    # Special validation for ADMIN_PASSWORD_HASH
    if var == "ADMIN_PASSWORD_HASH" and not validate_argon2_hash(value):
        invalid_vars.append((var, "not a valid Argon2 hash"))

if missing_vars or invalid_vars:
    logger.critical("=" * 70)
    logger.critical("FATAL ERROR: Invalid environment configuration!")
    logger.critical("=" * 70)

    if missing_vars:
        logger.critical("Missing variables:")
        for var in missing_vars:
            logger.critical(f"  - {var}")

    if invalid_vars:
        logger.critical("Invalid variables:")
        for var, reason in invalid_vars:
            logger.critical(f"  - {var}: {reason}")

    logger.critical("")
    logger.critical("The application cannot start with invalid configuration.")
    logger.critical("Run 'python generate_admin_password.py' to generate valid secrets.")
    logger.critical("=" * 70)

    print("\nFATAL ERROR: Invalid environment configuration!")
    print("=" * 70)

    if missing_vars:
        print("\nMissing variables:")
        for var in missing_vars:
            print(f"  - {var}")

    if invalid_vars:
        print("\nInvalid variables:")
        for var, reason in invalid_vars:
            print(f"  - {var}: {reason}")

    print("\n" + "=" * 70)
    print("Run: python generate_admin_password.py")
    print("Then add the generated values to your .env file or environment.")
    print("=" * 70 + "\n")
    sys.exit(1)

# Initialize encryption key
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
logger.info("Encryption key loaded and validated")

cipher_suite = Fernet(
    ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY
)

# CSRF protection will use session-based tokens
# No global secret needed - each session gets its own token
logger.info("CSRF protection enabled via session tokens")

# Initialize admin password hash
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
logger.info("Admin password hash loaded from environment")

# Initialize password hasher for API keys and admin auth
ph = PasswordHasher()

# Initialize Sentry SDK for error monitoring and performance tracing
sentry_dsn = os.environ.get("SENTRY_DSN")
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        send_default_pii=True,
        traces_sample_rate=1.0,
        profile_session_sample_rate=1.0,
        profile_lifecycle="trace",
        environment="Production",
        release=f"{config.APP_NAME}@{config.APP_VERSION}",
    )
    logger.info(f"Sentry SDK initialized for {config.APP_NAME}@{config.APP_VERSION}")
else:
    logger.info("Sentry SDK disabled (no DSN provided)")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
logger.info("Flask secret key loaded from environment")
logger.info(f"Flask application '{config.APP_NAME}' v{config.APP_VERSION} starting up")

# Track server start time to invalidate all previous admin sessions
SERVER_START_TIME = int(time.time())
logger.info(f"Server start time: {SERVER_START_TIME}")

os.makedirs(config.APP_NAME, exist_ok=True)

# Initialize database path and handler
db_path = os.path.join(config.APP_NAME, "data.db")
logger.info(f"Initializing database at {db_path}")

# Create DatabaseHandler instance for centralized database operations
db_handler = DatabaseHandler(db_path, logger)

# Initialize database schema
try:
    logger.info("Setting up database schema")

    # Table for tracking starred/watched repos
    db_handler.execute(
        """
        CREATE TABLE IF NOT EXISTS user_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            github_user_id INTEGER NOT NULL,
            repository_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            UNIQUE(github_user_id, repository_id, event_type)
        )
        """,
        commit=True,
        fetch=False,
    )
    logger.debug("user_events table created/verified")

    # Table for repository configurations
    db_handler.execute(
        """
        CREATE TABLE IF NOT EXISTS repositories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_id INTEGER NOT NULL UNIQUE,
            repo_full_name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            secret_encrypted TEXT NOT NULL,
            discord_webhook_url TEXT NOT NULL,
            enabled_events TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        commit=True,
        fetch=False,
    )
    logger.debug("repositories table created/verified")

    # Table for API keys (permissions as bitmap integer)
    db_handler.execute(
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            permissions INTEGER DEFAULT 0 CHECK (is_admin_key = 1 OR permissions > 0),
            rate_limit INTEGER DEFAULT 100,
            is_admin_key INTEGER DEFAULT 0
        )
        """,
        commit=True,
        fetch=False,
    )
    logger.debug("api_keys table created/verified")

    # Table for API rate limiting tracking
    # Stores only: key_id, first_request_time, request_count
    db_handler.execute(
        """
        CREATE TABLE IF NOT EXISTS api_rate_limit_tracking (
            api_key_id INTEGER PRIMARY KEY,
            first_request_time TIMESTAMP NOT NULL,
            request_count INTEGER DEFAULT 1,
            FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
        )
        """,
        commit=True,
        fetch=False,
    )
    logger.debug("api_rate_limit_tracking table created/verified")

    logger.info("Database initialization completed successfully")
except Exception as e:
    logger.critical(f"Database initialization failed: {e}")
    sys.exit(f"Database error: {e}")

# Initialize periodic task manager but don't start it yet
# It will be started by Gunicorn's post_fork hook (only in one worker)
# or by the if __name__ == "__main__" block for direct execution
task_manager = PeriodicTaskManager(db_handler=db_handler, log_manager=log_manager)
logger.info("Periodic task manager initialized (not started yet)")


# ============================================================================
# Signal Handler for Graceful Shutdown
# ============================================================================


class SignalHandler:
    """
    Handles shutdown signals (SIGINT, SIGTERM) to gracefully stop the application.
    Ensures database connections are closed and periodic tasks are stopped.
    """

    def __init__(self):
        self.shutdown_initiated = False

        # Register signal handlers (only works in main thread)
        try:
            signal.signal(signal.SIGINT, self._shutdown)
            signal.signal(signal.SIGTERM, self._shutdown)
            logger.info("Signal handlers registered (SIGINT, SIGTERM)")
        except ValueError:
            # Not in main thread (e.g., when running under Gunicorn)
            logger.debug("Signal handlers not registered (not in main thread)")

    def _shutdown(self, signum, frame):
        """
        Handle shutdown signals gracefully.

        Args:
            signum: Signal number
            frame: Current stack frame
        """
        if self.shutdown_initiated:
            logger.warning("Shutdown already in progress, ignoring duplicate signal")
            return

        self.shutdown_initiated = True
        signal_name = signal.Signals(signum).name
        logger.info(f"Received {signal_name}, initiating graceful shutdown...")

        try:
            # Run WAL checkpoint before closing connections
            logger.info("Running database WAL checkpoint...")
            db_handler.checkpoint_wal()
            logger.info("Database WAL checkpoint completed")
            
            # Close all database connections in DatabaseHandler
            logger.info("Closing database connections...")
            db_handler.close_all_connections()
            logger.info("Database connections closed")

            # Note: Periodic tasks run in daemon threads and will stop automatically
            logger.info("Periodic tasks will stop automatically (daemon threads)")

            logger.info("Graceful shutdown completed")

        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        finally:
            # Exit the application
            sys.exit(0)


# Initialize signal handler
signal_handler = SignalHandler()


def get_db():
    """
    Retrieves a SQLite database connection for the current Flask application context.
    Reuses connection for the entire request lifecycle.
    Connection is automatically committed and closed at request end.
    """
    if "db" not in g:
        g.db = sqlite3.connect(
            os.path.join(config.APP_NAME, "data.db"),
            timeout=10.0,  # Wait up to 10 seconds for locks
            check_same_thread=False,  # Allow connection to be used across threads with gunicorn
        )
        g.db.row_factory = sqlite3.Row

        # Set optimized PRAGMA settings
        # Note: WAL mode is already set during database initialization
        try:
            g.db.execute("PRAGMA synchronous=NORMAL")  # Faster than FULL, still safe with WAL
            g.db.execute("PRAGMA cache_size=-32000")  # 32MB cache (reduced from 64MB for Docker)
            g.db.execute("PRAGMA temp_store=MEMORY")  # Store temp tables in memory
            g.db.execute("PRAGMA busy_timeout=10000")  # Wait up to 10s for locks
        except sqlite3.Error as e:
            logger.warning(f"Error setting database PRAGMAs: {e}")

        logger.debug("New database connection established")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):  # pylint: disable=unused-argument
    """
    Commits and closes the database connection at the end of the Flask application context.
    All changes made during the request are committed here unless there was an exception.
    """
    db = g.pop("db", None)
    if db is not None:
        try:
            if exception is None:
                # Only commit if no exception occurred
                db.commit()
                logger.debug("Database changes committed")
        except Exception as e:
            logger.error(f"Error committing database changes: {e}")
            db.rollback()
        finally:
            db.close()
            logger.debug("Database connection closed")
    if exception:
        logger.error(f"App context teardown with exception: {exception}")


# ============================================================================
# Permissions Bitmap Setup
# ============================================================================

# Define all route permissions here (add as needed)
PERMISSION_KEYS = [
    "generate-secret",  # bit 0, value 1
    "repositories-add",  # bit 1, value 2
    "repositories-verify",  # bit 2, value 4
    "repositories-update",  # bit 3, value 8
    "repositories-delete",  # bit 4, value 16
    "events-list",  # bit 5, value 32
    "permissions-list",  # bit 6, value 64
    "permissions-calculate",  # bit 7, value 128
    "permissions-decode",  # bit 8, value 256
]
bitmap_handler = BitmapHandler(PERMISSION_KEYS, logger)

# ============================================================================
# Initialize Security and Authentication Handlers
# ============================================================================

# Initialize security handler for encryption and signature verification
security_handler = SecurityHandler(cipher_suite, logger)

# Initialize authentication handler for API keys and admin auth
auth_handler = AuthenticationHandler(
    password_hasher=ph,
    admin_password_hash=ADMIN_PASSWORD_HASH,
    get_db_func=get_db,
    bitmap_handler=bitmap_handler,
    server_start_time=SERVER_START_TIME,
    logger=logger,
)

# Create wrapper functions for backward compatibility with existing code
encrypt_secret = security_handler.encrypt_secret
decrypt_secret = security_handler.decrypt_secret
verify_secret = security_handler.verify_secret
verify_github_signature = security_handler.verify_github_signature

hash_api_key = auth_handler.hash_api_key
verify_api_key = auth_handler.verify_api_key
check_api_key_in_db = auth_handler.check_api_key_in_db
verify_admin_password = auth_handler.verify_admin_password
check_rate_limit = auth_handler.check_rate_limit
check_api_key_permission = auth_handler.check_api_key_permission
require_api_key_or_csrf = auth_handler.require_api_key_or_csrf
require_admin_auth = auth_handler.require_admin_auth

logger.info("Security and authentication handlers initialized")


def verify_discord_webhook(webhook_url: str) -> bool:
    """
    Verifies that a Discord webhook URL is valid and active.

    Args:
        webhook_url (str): The Discord webhook URL to verify.

    Returns:
        bool: True if the webhook is valid and active, False otherwise.
    """
    try:
        logger.debug(f"Verifying Discord webhook: {webhook_url[:50]}...")
        response = requests.get(webhook_url, timeout=5)
        if response.status_code == 200:
            logger.debug("Discord webhook verification successful")
            return True
        logger.warning(f"Discord webhook verification failed: HTTP {response.status_code}")
        return False
    except requests.RequestException as e:
        logger.error(f"Discord webhook verification error: {e}")
        return False


def extract_repo_info_from_url(repo_url: str) -> tuple[str, str] | None:
    """
    Extracts owner and repo name from a GitHub repository URL.

    Args:
        repo_url (str): The GitHub repository URL.

    Returns:
        tuple[str, str] | None: A tuple of (owner, repo) or None if invalid.
    """
    try:
        # Remove trailing slashes and .git
        repo_url = repo_url.rstrip("/").rstrip(".git")

        # Handle various GitHub URL formats
        if "github.com/" in repo_url:
            parts = repo_url.split("github.com/")[-1].split("/")
            if len(parts) >= 2:
                logger.debug(f"Extracted repo info: {parts[0]}/{parts[1]}")
                return parts[0], parts[1]
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error(f"Failed to extract repo info from URL '{repo_url}': {e}")

    logger.warning(f"Invalid GitHub repository URL: {repo_url}")
    return None


def fetch_repo_data_from_github(owner: str, repo: str) -> dict | None:
    """
    Fetches repository data from GitHub API.

    Args:
        owner (str): The repository owner.
        repo (str): The repository name.

    Returns:
        dict | None: Repository data including repo_id and owner_id, or None if error.
    """
    try:
        logger.debug(f"Fetching repository data from GitHub: {owner}/{repo}")
        response = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=5,
        )

        if response.status_code == 200:
            data = response.json()
            logger.info(
                f"Successfully fetched GitHub repo data: {data['full_name']} (ID: {data['id']})"
            )
            return {
                "repo_id": data["id"],
                "repo_full_name": data["full_name"],
                "owner_id": data["owner"]["id"],
            }
        logger.warning(f"Failed to fetch GitHub repo data: HTTP {response.status_code}")
    except requests.RequestException as e:
        logger.error(f"GitHub API request failed for {owner}/{repo}: {e}")

    return None


def send_discord_notification(webhook_url: str, event_data: dict, event_type: str) -> bool:
    """
    Sends a notification to Discord about a new GitHub event.

    Args:
        webhook_url (str): The Discord webhook URL.
        event_data (dict): The GitHub event payload.
        event_type (str): The event type (star or watch).

    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        event_names = {"star": "star added", "watch": "watcher added"}

        event_colors = {
            "star": 0xFFC107,  # Amber for stars
            "watch": 0x1ABC9C,  # Teal for watches
        }

        user_login = event_data["sender"]["login"]
        repo_name = event_data["repository"]["full_name"]

        logger.info(
            f"Sending Discord notification: {event_type} event by {user_login} on {repo_name}"
        )

        payload = {
            "username": "GitHub Events Bot",
            "avatar_url": "https://cdn-icons-png.flaticon.com/512/616/616489.png",
            "embeds": [
                {
                    "author": {
                        "name": user_login,
                        "icon_url": event_data["sender"]["avatar_url"],
                        "url": event_data["sender"]["html_url"],
                    },
                    "title": (f"[{repo_name}] " f"New {event_names.get(event_type, event_type)}"),
                    "url": event_data["repository"]["html_url"],
                    "color": event_colors.get(event_type, 0x1ABC9C),
                    "footer": {"text": f"GitHub {event_type.capitalize()} Event"},
                }
            ],
        }

        response = requests.post(webhook_url, json=payload, timeout=5)
        response.raise_for_status()
        logger.info(f"Discord notification sent successfully: {event_type} by {user_login}")
        return True
    except (KeyError, requests.RequestException) as e:
        logger.error(f"Failed to send Discord notification: {e}")
        return False


def has_user_triggered_event_before(
    github_user_id: int, repository_id: int, event_type: str
) -> bool:
    """
    Checks if a user has already triggered a specific event for a repository.

    Args:
        github_user_id (int): The GitHub user ID.
        repository_id (int): The GitHub repository ID.
        event_type (str): The event type (star or watch).

    Returns:
        bool: True if the user has triggered this event before, False otherwise.
    """
    db = get_db()
    try:
        cursor = db.execute(
            "SELECT 1 FROM user_events WHERE github_user_id = ? "
            "AND repository_id = ? AND event_type = ? LIMIT 1",
            (github_user_id, repository_id, event_type),
        )
        result = cursor.fetchone() is not None
        logger.debug(
            "User %s has %s triggered %s on repo %s",
            github_user_id,
            "already" if result else "not",
            event_type,
            repository_id,
        )
        return result
    except sqlite3.Error as e:
        logger.error(f"Database error checking user event: {e}")
        return False


def add_user_event(github_user_id: int, repository_id: int, event_type: str):
    """
    Records that a user has triggered an event for a repository.

    Args:
        github_user_id (int): The GitHub user ID.
        repository_id (int): The GitHub repository ID.
        event_type (str): The event type (star or watch).
    """
    try:
        db = get_db()
        db.execute(
            "INSERT OR IGNORE INTO user_events "
            "(github_user_id, repository_id, event_type) VALUES (?, ?, ?)",
            (github_user_id, repository_id, event_type),
        )
        logger.info(f"Recorded {event_type} event: user {github_user_id} on repo {repository_id}")
    except sqlite3.Error as e:
        logger.error(f"Database error adding user event: {e}")


def get_repository_by_id(repo_id: int) -> dict | None:
    """
    Retrieves repository configuration by repository ID.

    Args:
        repo_id (int): The GitHub repository ID.

    Returns:
        dict | None: Repository configuration or None if not found.
    """
    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM repositories WHERE repo_id = ? LIMIT 1", (repo_id,))
        row = cursor.fetchone()
        if row:
            logger.debug(f"Retrieved repository config for repo_id {repo_id}")
            return dict(row)
        logger.debug(f"Repository not found: repo_id {repo_id}")
        return None
    except sqlite3.Error as e:
        logger.error(f"Database error getting repository: {e}")
        return None


# ============================================================================
# Register Route Blueprints
# ============================================================================

from routes import register_blueprints

# Prepare helper functions and objects for routes
route_helpers = {
    "logger": logger,
    "get_db": get_db,
    "get_repository_by_id": get_repository_by_id,
    "decrypt_secret": decrypt_secret,
    "verify_github_signature": verify_github_signature,
    "has_user_triggered_event_before": has_user_triggered_event_before,
    "send_discord_notification": send_discord_notification,
    "add_user_event": add_user_event,
    "require_api_key_or_csrf": require_api_key_or_csrf,
    "extract_repo_info_from_url": extract_repo_info_from_url,
    "fetch_repo_data_from_github": fetch_repo_data_from_github,
    "verify_discord_webhook": verify_discord_webhook,
    "encrypt_secret": encrypt_secret,
    "verify_secret": verify_secret,
    "require_admin_auth": require_admin_auth,
    "verify_admin_password": verify_admin_password,
    "hash_api_key": hash_api_key,
    "bitmap_handler": bitmap_handler,
}

# Register all route blueprints (web, api, admin)
register_blueprints(app, route_helpers)
logger.info("Route blueprints registered successfully")


if __name__ == "__main__":
    # When running directly (not via Gunicorn), start the periodic tasks and Flask dev server
    task_manager.start_all_tasks()
    logger.info("Periodic tasks started (direct execution mode)")

    logger.info(f"Starting {config.APP_NAME} v{config.APP_VERSION} on port 5000")
    # Debug mode disabled for production security
    app.run(host="0.0.0.0", port=5000, debug=False)
