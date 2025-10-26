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

import hashlib
import hmac
import os
import re
import secrets
import signal
import sqlite3
import sys
import time
from functools import wraps

import requests
import sentry_sdk
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, g, jsonify, render_template, request, session, send_file

# Add .config folder to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.config'))

import config  # type: ignore  # config is in .config folder, added to path above
from CustomModules.LogHandler import LogManager
from CustomModules.BitmapHandler import BitmapHandler
from CustomModules.DatabaseHandler import DatabaseHandler
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
    pattern = r'^\$argon2id?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$'
    if not re.match(pattern, hash_string):
        return False

    # Additional validation: verify it starts with correct prefix
    return hash_string.startswith('$argon2')


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
    if var == "ADMIN_PASSWORD_HASH":
        if not validate_argon2_hash(value):
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
        fetch=False
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
        fetch=False
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
        fetch=False
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
        fetch=False
    )
    logger.debug("api_rate_limit_tracking table created/verified")

    logger.info("Database initialization completed successfully")
except Exception as e:
    logger.critical(f"Database initialization failed: {e}")
    sys.exit(f"Database error: {e}")

# Initialize periodic task manager but don't start it yet
# It will be started by Gunicorn's post_fork hook (only in one worker)
# or by the if __name__ == "__main__" block for direct execution
task_manager = PeriodicTaskManager(
    db_handler=db_handler,
    log_manager=log_manager
)
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
            check_same_thread=False  # Allow connection to be used across threads with gunicorn
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
# Helper Functions
# ============================================================================


def encrypt_secret(secret: str) -> str:
    """
    Encrypts a secret for secure storage.

    Args:
        secret (str): The plaintext secret to encrypt.

    Returns:
        str: The encrypted secret as a base64 string.
    """
    logger.debug("Encrypting secret")
    return cipher_suite.encrypt(secret.encode()).decode()


def decrypt_secret(encrypted_secret: str) -> str:
    """
    Decrypts a stored secret.

    Args:
        encrypted_secret (str): The encrypted secret string.

    Returns:
        str: The decrypted plaintext secret.
    """
    logger.debug("Decrypting secret")
    return cipher_suite.decrypt(encrypted_secret.encode()).decode()


def verify_secret(plaintext_secret: str, encrypted_secret: str) -> bool:
    """
    Verifies a plaintext secret against an encrypted stored secret.

    Args:
        plaintext_secret (str): The plaintext secret to verify.
        encrypted_secret (str): The encrypted secret to compare against.

    Returns:
        bool: True if the secret matches, False otherwise.
    """
    try:
        stored_secret = decrypt_secret(encrypted_secret)
        result = hmac.compare_digest(plaintext_secret, stored_secret)
        logger.debug(f"Secret verification: {'success' if result else 'failed'}")
        return result
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error(f"Secret verification error: {e}")
        return False


def verify_github_signature(secret: str, signature_header: str, payload: bytes) -> bool:
    """
    Validates the GitHub webhook signature using HMAC SHA-256.

    Args:
        secret (str): The webhook secret.
        signature_header (str): The 'x-hub-signature-256' header value.
        payload (bytes): The request body.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    if not signature_header:
        logger.warning("GitHub signature validation failed: missing signature header")
        return False

    try:
        sha_name, signature = signature_header.split("=", 1)
    except ValueError:
        logger.warning("GitHub signature validation failed: malformed signature header")
        return False

    if sha_name != "sha256":
        logger.warning(
            f"GitHub signature validation failed: unsupported hash algorithm '{sha_name}'"
        )
        return False

    mac = hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256)
    expected_signature = mac.hexdigest()
    result = hmac.compare_digest(expected_signature, signature)
    if result:
        logger.debug("GitHub signature validation successful")
    else:
        logger.warning("GitHub signature validation failed: signature mismatch")
    return result


## ============================================================================
# Permissions Bitmap Setup
## ============================================================================

# Define all route permissions here (add as needed)
PERMISSION_KEYS = [
    "generate-secret",
    "repositories-add",
    "repositories-verify",
    "repositories-update",
    "repositories-delete",
    # Add more for each route as needed
]
bitmap_handler = BitmapHandler(PERMISSION_KEYS)

# ============================================================================
# API Authentication Functions
# ============================================================================


def hash_api_key(api_key: str) -> str:
    """
    Hashes an API key using Argon2id.

    Args:
        api_key (str): The plaintext API key to hash.

    Returns:
        str: The hashed API key.
    """
    logger.debug("Hashing API key")
    return ph.hash(api_key)


def verify_api_key(api_key: str, key_hash: str) -> bool:
    """
    Verifies an API key against its hash.

    Args:
        api_key (str): The plaintext API key to verify.
        key_hash (str): The stored hash to verify against.

    Returns:
        bool: True if the key matches, False otherwise.
    """
    try:
        ph.verify(key_hash, api_key)
        logger.debug("API key verification successful")
        return True
    except VerifyMismatchError:
        logger.debug("API key verification failed")
        return False


def check_api_key_in_db(api_key: str) -> bool:
    """
    Checks if an API key is valid and active in the database.
    Updates the last_used timestamp if valid.

    Args:
        api_key (str): The API key to check.

    Returns:
        bool: True if valid and active, False otherwise.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, key_hash, permissions, rate_limit, is_admin_key FROM api_keys WHERE is_active = 1"
    )
    keys = cursor.fetchall()

    for key in keys:
        if verify_api_key(api_key, key["key_hash"]):
            g.api_key_id = key["id"]
            g.is_admin_key = bool(key["is_admin_key"] if key["is_admin_key"] is not None else 0)
            g.api_key_permissions = key["permissions"] or 0  # bitmap int
            g.api_key_rate_limit = key["rate_limit"] if key["rate_limit"] is not None else 100
            db.execute(
                "UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?",
                (key["id"],)
            )
            logger.info("Valid API key used (ID: %s, Admin: %s)", key["id"], g.is_admin_key)
            return True
    logger.warning("Invalid or inactive API key attempted")
    return False


def verify_admin_password(password: str) -> bool:
    """
    Verifies the admin password against the stored hash.

    Args:
        password (str): The plaintext password to verify.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    if not ADMIN_PASSWORD_HASH:
        logger.warning("Admin password verification failed: no hash configured")
        return False

    try:
        ph.verify(ADMIN_PASSWORD_HASH, password)
        logger.info("Admin password verification successful")
        return True
    except VerifyMismatchError:
        logger.warning("Admin password verification failed")
        return False


def check_rate_limit(api_key_id: int, rate_limit: int) -> tuple[bool, int]:
    """
    Check if an API key has exceeded its rate limit.
    
    Rate limits are enforced per hour. Admin keys (rate_limit=0) have unlimited access.
    Tracks usage with: api_key_id, first_request_time, request_count.
    The tracking window is reset by the periodic cleanup task, not here.
    
    Args:
        api_key_id (int): The ID of the API key
        rate_limit (int): The hourly rate limit (0 = unlimited)
    
    Returns:
        tuple[bool, int]: (True if within rate limit, current request count)
    """
    # Admin keys or unlimited rate limit
    if rate_limit == 0:
        return True, 0
    
    db = get_db()
    cursor = db.cursor()
    
    # Get current tracking record for this API key
    cursor.execute(
        """
        SELECT first_request_time, request_count 
        FROM api_rate_limit_tracking 
        WHERE api_key_id = ?
        """,
        (api_key_id,)
    )
    
    result = cursor.fetchone()
    current_time = int(time.time())
    
    if result:
        request_count = result["request_count"]
        
        # Check if rate limit is exceeded
        if request_count >= rate_limit:
            logger.warning(
                "Rate limit exceeded for API key ID %s: %s/%s requests in current hour",
                api_key_id, request_count, rate_limit
            )
            return False, request_count
        
        # Increment request count
        db.execute(
            """
            UPDATE api_rate_limit_tracking 
            SET request_count = request_count + 1 
            WHERE api_key_id = ?
            """,
            (api_key_id,)
        )
        
        logger.debug(
            "Rate limit check passed for API key ID %s: %s/%s requests",
            api_key_id, request_count + 1, rate_limit
        )
        return True, request_count + 1
    else:
        # First request for this API key - create tracking record
        db.execute(
            """
            INSERT INTO api_rate_limit_tracking (api_key_id, first_request_time, request_count) 
            VALUES (?, ?, 1)
            """,
            (api_key_id, current_time)
        )
        
        logger.debug(
            "Rate limit check passed for API key ID %s: 1/%s requests (new tracking window)",
            api_key_id, rate_limit
        )
        return True, 1
    return True


def check_api_key_permission(endpoint: str, required_permission: str) -> bool:
    """
    Check if the current API key has the required permission for a specific endpoint.

    Args:
        endpoint (str): The endpoint to check ('webhook', 'repositories', 'csrf').
        required_permission (str): The permission to check ('r' for read, 'w' for write).

    Returns:
        bool: True if the API key has the required permission, False otherwise.
    """
    permissions_bitmap = getattr(g, 'api_key_permissions', 0)
    return bitmap_handler.check_key_in_bitkey(endpoint, permissions_bitmap)


def require_api_key_or_csrf(f):
    """
    Decorator to require either a valid API key or a valid CSRF token.
    This allows the frontend to access API routes securely while requiring API keys
    for programmatic access. CSRF tokens are session-specific and prevent
    cross-site request forgery attacks.

    Anti-replay protection:
    - Each token can only be used once (nonce)
    - Tokens expire after 5 minutes
    - Browser fingerprinting detects session hijacking
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for API key in Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            api_key = auth_header[7:]  # Remove "Bearer " prefix
            if check_api_key_in_db(api_key):
                # Check rate limit after successful authentication
                within_limit, current_count = check_rate_limit(g.api_key_id, g.api_key_rate_limit)
                
                if not within_limit:
                    logger.warning("API route access denied: rate limit exceeded for API key ID %s", g.api_key_id)
                    response = jsonify({"error": "Rate limit exceeded"})
                    response.headers["RateLimit"] = f"{current_count}/{g.api_key_rate_limit}"
                    return response, 429
                
                # Execute the route function
                result = f(*args, **kwargs)
                
                # Add rate limit header to successful responses
                if isinstance(result, tuple):
                    response, status_code = result[0], result[1] if len(result) > 1 else 200
                else:
                    response, status_code = result, 200
                
                # Ensure response is a Response object
                if not hasattr(response, 'headers'):
                    response = jsonify(response) if not isinstance(response, str) else response
                
                # Add rate limit header if we have a rate limit
                if g.api_key_rate_limit > 0:
                    if hasattr(response, 'headers'):
                        response.headers["RateLimit"] = f"{current_count}/{g.api_key_rate_limit}"
                
                return response, status_code if isinstance(result, tuple) else response
                
            logger.warning("API route access denied: invalid API key")
            return jsonify({"error": "Invalid API key"}), 401

        # Check for CSRF token in custom header
        csrf_token = request.headers.get("X-CSRF-Token")
        if csrf_token:
            session_token = session.get("csrf_token")
            if not session_token:
                logger.warning(
                    "API route access denied: no CSRF token in session from %s",
                    request.remote_addr
                )
                return jsonify({"error": "Invalid CSRF token"}), 403

            # Validate token matches
            if not hmac.compare_digest(csrf_token, session_token):
                logger.warning(
                    "API route access denied: CSRF token mismatch from %s",
                    request.remote_addr
                )
                return jsonify({"error": "Invalid CSRF token"}), 403

            # Check token timestamp (5 minute expiry)
            token_timestamp = session.get("csrf_token_timestamp", 0)
            current_time = int(request.headers.get("X-Request-Time", "0"))

            # Validate timestamp exists and is recent
            if current_time > 0:
                time_diff = abs(current_time - token_timestamp)
                if time_diff > 300:  # 5 minutes = 300 seconds
                    logger.warning(
                        "API route access denied: "
                        "CSRF token expired (%d seconds old) from %s",
                        time_diff,
                        request.remote_addr
                    )
                    # Generate new token
                    session["csrf_token"] = secrets.token_hex(32)
                    req_time = request.headers.get("X-Request-Time", "0")
                    session["csrf_token_timestamp"] = int(req_time)
                    return jsonify({
                        "error": "CSRF token expired",
                        "new_token": session["csrf_token"]
                    }), 403

            # Check nonce to prevent replay attacks
            nonce = request.headers.get("X-Request-Nonce")
            if nonce:
                used_nonces = session.get("used_nonces", [])
                if nonce in used_nonces:
                    logger.warning(
                        "API route access denied: "
                        "nonce replay detected from %s (nonce: %s)",
                        request.remote_addr,
                        nonce[:16]
                    )
                    return jsonify({"error": "Replay attack detected"}), 403

                # Store nonce (keep last 100 to prevent memory bloat)
                used_nonces.append(nonce)
                if len(used_nonces) > 100:
                    used_nonces = used_nonces[-100:]
                session["used_nonces"] = used_nonces

            # Browser fingerprinting - detect session hijacking
            user_agent = request.headers.get("User-Agent", "")
            stored_ua = session.get("user_agent")

            if stored_ua and stored_ua != user_agent:
                logger.warning(
                    "API route access denied: "
                    "User-Agent changed (possible session hijacking) from %s",
                    request.remote_addr
                )
                return jsonify({"error": "Session validation failed"}), 403

            if not stored_ua:
                session["user_agent"] = user_agent

            logger.debug("API route access granted: valid CSRF token")
            return f(*args, **kwargs)

        logger.warning(
            "API route access denied: no valid API key or CSRF token from %s",
            request.remote_addr
        )
        return jsonify(
            {"error": "Unauthorized. Use API key or access via the web interface."}
        ), 401

    return decorated_function


def require_admin_auth(f):
    """
    Decorator to require admin authentication via session or admin API key.
    Enforces 5-minute session timeout for security.
    Invalidates all sessions created before server startup.
    Refreshes session timestamp on each successful validation (sliding session).
    Also accepts admin API keys for programmatic access.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for admin API key first
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            api_key = auth_header[7:]  # Remove "Bearer " prefix
            if check_api_key_in_db(api_key):
                # Check if this is an admin key
                if getattr(g, 'is_admin_key', False):
                    logger.info("Admin route access granted via admin API key (ID: %s)", g.api_key_id)
                    return f(*args, **kwargs)
                else:
                    logger.warning(
                        "Admin route access denied: API key is not an admin key from %s",
                        request.remote_addr
                    )
                    return jsonify({"error": "Admin access required"}), 403
            else:
                logger.warning("Admin route access denied: invalid API key from %s", request.remote_addr)
                return jsonify({"error": "Invalid API key"}), 401
        
        # Check for session-based admin auth
        if not session.get("admin_authenticated"):
            # Only log warning for non-GET requests (actual access attempts)
            if request.method != "GET":
                logger.warning(
                    "Admin route access denied: not authenticated from %s",
                    request.remote_addr
                )
            return jsonify({"error": "Unauthorized"}), 401

        # Invalidate sessions created before server startup
        admin_login_time = session.get("admin_login_time", 0)
        if admin_login_time < SERVER_START_TIME:
            logger.warning(
                "Admin session invalidated: created before server startup from %s",
                request.remote_addr
            )
            session.pop("admin_authenticated", None)
            session.pop("admin_login_time", None)
            return jsonify({"error": "Session invalidated. Please log in again."}), 401

        # Check session timeout (5 minutes)
        current_time = int(time.time())
        session_age = current_time - admin_login_time

        if session_age > 300:  # 5 minutes = 300 seconds
            logger.warning(
                "Admin session expired (%d seconds old) from %s",
                session_age,
                request.remote_addr
            )
            session.pop("admin_authenticated", None)
            session.pop("admin_login_time", None)
            return jsonify({"error": "Session expired"}), 401

        # Refresh session timestamp (sliding session)
        session["admin_login_time"] = current_time
        session.modified = True

        return f(*args, **kwargs)

    return decorated_function


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
        logger.warning(
            f"Discord webhook verification failed: HTTP {response.status_code}"
        )
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


def send_discord_notification(
    webhook_url: str, event_data: dict, event_type: str
) -> bool:
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
                    "title": (
                        f"[{repo_name}] "
                        f"New {event_names.get(event_type, event_type)}"
                    ),
                    "url": event_data["repository"]["html_url"],
                    "color": event_colors.get(event_type, 0x1ABC9C),
                    "footer": {"text": f"GitHub {event_type.capitalize()} Event"},
                }
            ],
        }

        response = requests.post(webhook_url, json=payload, timeout=5)
        response.raise_for_status()
        logger.info(
            f"Discord notification sent successfully: {event_type} by {user_login}"
        )
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
            'already' if result else 'not',
            event_type,
            repository_id
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
        logger.info(
            f"Recorded {event_type} event: user {github_user_id} on repo {repository_id}"
        )
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
        cursor = db.execute(
            "SELECT * FROM repositories WHERE repo_id = ? LIMIT 1", (repo_id,)
        )
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
# Web Routes
# ============================================================================


@app.route("/", methods=["GET"])
def index():
    """
    Serves the frontend HTML page with CSRF token generation.
    Generates a unique CSRF token for this session to prevent CSRF attacks.
    Also initializes timestamp for token expiry validation.
    """
    try:
        # Generate CSRF token if not already in session
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
            # Pseudo-timestamp for initial value
            pseudo_ts = int(secrets.token_urlsafe(8), 36) % 1000000000
            session["csrf_token_timestamp"] = pseudo_ts
            session["used_nonces"] = []
            logger.debug("Generated new CSRF token for session")

        logger.debug(f"Web interface accessed from {request.remote_addr}")
        return render_template("index.html", csrf_token=session["csrf_token"])
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error(f"Error serving frontend: {e}")
        return jsonify(
            {
                "app": config.APP_NAME,
                "version": config.APP_VERSION,
                "status": "running",
                "message": "Frontend not available. Use API endpoints.",
            }
        )


@app.route("/webhook", methods=["POST"])
def handle_webhook():  # pylint: disable=too-many-return-statements,too-many-branches
    """
    Handles incoming GitHub webhook events (star, watch, ping).

    This endpoint:
    - Handles GitHub's ping event for webhook verification
    - Validates webhook signatures
    - Processes star and watch events
    - Sends Discord notifications for first-time events
    """
    # Handle ping event from GitHub webhook setup
    event_type = request.headers.get("x-github-event")
    logger.info(f"Received webhook event: {event_type} from {request.remote_addr}")

    if event_type == "ping":
        logger.info("Webhook ping event received and acknowledged")
        return jsonify({"message": "Webhook received and verified"}), 200

    # Validate JSON payload
    if not request.is_json:
        logger.warning("Webhook rejected: not JSON")
        return jsonify({"error": "Expected application/json"}), 400

    data = request.get_json(silent=True)
    if not data:
        logger.warning("Webhook rejected: malformed or empty JSON")
        return jsonify({"error": "Malformed or empty JSON"}), 400

    # Extract repository information
    repo_id = data.get("repository", {}).get("id")
    if not repo_id:
        logger.warning("Webhook rejected: missing repository.id")
        return jsonify({"error": "Missing repository.id"}), 400

    # Get repository configuration
    repo_config = get_repository_by_id(repo_id)
    if not repo_config:
        logger.warning(f"Webhook rejected: repository {repo_id} not configured")
        return jsonify({"error": "Repository not configured"}), 404

    # Validate webhook signature
    signature_header = request.headers.get("x-hub-signature-256")
    if not signature_header:
        logger.warning(f"Webhook rejected for repo {repo_id}: missing signature")
        return jsonify({"error": "Missing signature"}), 403

    # Decrypt secret and validate signature
    try:
        secret = decrypt_secret(repo_config["secret_encrypted"])
        if not verify_github_signature(secret, signature_header, request.data):
            logger.warning(f"Webhook rejected for repo {repo_id}: invalid signature")
            return jsonify({"error": "Invalid signature"}), 403
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error(f"Error validating signature for repo {repo_id}: {e}")
        return jsonify({"error": "Signature validation failed"}), 403

    # Check if event type is supported
    if event_type not in ["star", "watch"]:
        logger.warning(f"Unsupported event type: {event_type} for repo {repo_id}")
        return jsonify({"error": "Unsupported event type"}), 422

    # Check if this event type is enabled for this repository
    enabled_events = repo_config["enabled_events"].split(",")
    if event_type not in enabled_events:
        logger.info(f"{event_type} event received but not enabled for repo {repo_id}")
        return (
            jsonify(
                {"message": f"{event_type} events not enabled for this repository"}
            ),
            200,
        )

    # Check action
    action = data.get("action")
    if action not in ("created", "started"):  # 'started' is for watch events
        logger.debug(
            f"Action '{action}' not processed for {event_type} on repo {repo_id}"
        )
        return jsonify({"message": f"Action '{action}' not processed"}), 200

    # Get sender information
    sender_id = data.get("sender", {}).get("id")
    sender_login = data.get("sender", {}).get("login", "unknown")
    if sender_id is None:
        logger.warning(f"Webhook rejected for repo {repo_id}: missing sender ID")
        return jsonify({"error": "Missing sender ID"}), 400

    # Check if user has already triggered this event
    if not has_user_triggered_event_before(sender_id, repo_id, event_type):
        logger.info(
            "Processing first-time %s from %s (%s) on repo %s",
            event_type,
            sender_login,
            sender_id,
            repo_id
        )
        if send_discord_notification(
            repo_config["discord_webhook_url"], data, event_type
        ):
            add_user_event(sender_id, repo_id, event_type)
            logger.info(
                "Successfully processed %s event from %s on repo %s",
                event_type,
                sender_login,
                repo_id
            )
            return jsonify({"message": "Event processed and notification sent"}), 200
        logger.error(
            "Failed to send Discord notification for %s from %s on repo %s",
            event_type,
            sender_login,
            repo_id
        )
        return jsonify({"error": "Failed to send Discord notification"}), 500

    logger.debug(
        "Duplicate %s event from %s (%s) on repo %s - ignored",
        event_type,
        sender_login,
        sender_id,
        repo_id
    )
    return jsonify({"message": "Event already processed for this user"}), 200


# ============================================================================
# API Routes for Frontend
# ============================================================================


@app.route("/api/generate-secret", methods=["GET"])
@require_api_key_or_csrf
def api_generate_secret():
    """
    Generates a cryptographically secure random secret.
    """
    logger.debug(f"Secret generation requested from {request.remote_addr}")
    secret = secrets.token_urlsafe(32)
    return jsonify({"secret": secret}), 200


@app.route("/api/repositories", methods=["POST"])
@require_api_key_or_csrf
def api_add_repository():  # pylint: disable=too-many-return-statements
    """
    Adds a new repository configuration.

    Expected JSON payload:
    {
        "repo_url": "https://github.com/owner/repo",
        "secret": "webhook_secret",
        "discord_webhook_url": "https://discord.com/api/webhooks/...",
        "enabled_events": "star,watch"
    }
    """
    logger.info(f"API: Add repository request from {request.remote_addr}")
    data = request.get_json(silent=True)
    if not data:
        logger.warning("API: Add repository rejected - missing JSON payload")
        return jsonify({"error": "Missing JSON payload"}), 400

    repo_url = data.get("repo_url", "").strip()
    secret = data.get("secret", "").strip()
    discord_webhook_url = data.get("discord_webhook_url", "").strip()
    enabled_events = data.get("enabled_events", "").strip()

    # Validate inputs
    if not all([repo_url, secret, discord_webhook_url, enabled_events]):
        logger.warning("API: Add repository rejected - missing required fields")
        return jsonify({"error": "Missing required fields"}), 400

    # Validate enabled events
    events = enabled_events.split(",")
    valid_events = {"star", "watch"}
    if not all(event in valid_events for event in events):
        logger.warning(
            f"API: Add repository rejected - invalid event types: {enabled_events}"
        )
        return (
            jsonify({"error": "Invalid event types. Must be 'star' and/or 'watch'"}),
            400,
        )

    # Extract owner and repo from URL
    repo_info = extract_repo_info_from_url(repo_url)
    if not repo_info:
        logger.warning(f"API: Add repository rejected - invalid URL: {repo_url}")
        return jsonify({"error": "Invalid GitHub repository URL"}), 400

    owner, repo_name = repo_info

    # Fetch repository data from GitHub
    github_data = fetch_repo_data_from_github(owner, repo_name)
    if not github_data:
        logger.error(f"API: Failed to fetch GitHub data for {owner}/{repo_name}")
        return (
            jsonify(
                {
                    "error": "Could not fetch repository data from GitHub. Please check the URL."
                }
            ),
            400,
        )

    # Verify Discord webhook
    if not verify_discord_webhook(discord_webhook_url):
        logger.warning(
            f"API: Add repository rejected - invalid Discord webhook for {owner}/{repo_name}"
        )
        return jsonify({"error": "Discord webhook URL is invalid or inactive"}), 400

    # Encrypt the secret
    secret_encrypted = encrypt_secret(secret)

    # Store in database
    db = get_db()
    try:
        db.execute(
            """INSERT INTO repositories (repo_id, repo_full_name, owner_id,
            secret_encrypted, discord_webhook_url, enabled_events)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (
                github_data["repo_id"],
                github_data["repo_full_name"],
                github_data["owner_id"],
                secret_encrypted,
                discord_webhook_url,
                enabled_events,
            ),
        )
        logger.info(
            "API: Repository added successfully: %s (ID: %s) - Events: %s",
            github_data['repo_full_name'],
            github_data['repo_id'],
            enabled_events
        )
        return (
            jsonify(
                {
                    "message": "Repository added successfully",
                    "repo_full_name": github_data["repo_full_name"],
                }
            ),
            201,
        )
    except sqlite3.IntegrityError:
        logger.warning(
            "API: Repository already exists: %s (ID: %s)",
            github_data['repo_full_name'],
            github_data['repo_id']
        )
        return jsonify({"error": "Repository already exists in the database"}), 409
    except sqlite3.Error as e:
        logger.error(
            "API: Database error adding repository %s: %s",
            github_data['repo_full_name'],
            e
        )
        return jsonify({"error": f"Database error: {e}"}), 500


@app.route("/api/repositories/verify", methods=["POST"])
@require_api_key_or_csrf
def api_verify_repository():  # pylint: disable=too-many-return-statements
    """
    Verifies repository credentials for editing/deleting.

    Expected JSON payload:
    {
        "repo_url": "https://github.com/owner/repo",
        "secret": "webhook_secret",
        "discord_webhook_url": "https://discord.com/api/webhooks/..."
    }
    """
    logger.info(f"API: Verify repository request from {request.remote_addr}")
    data = request.get_json(silent=True)
    if not data:
        logger.warning("API: Verify repository rejected - missing JSON payload")
        return jsonify({"error": "Missing JSON payload"}), 400

    repo_url = data.get("repo_url", "").strip()
    secret = data.get("secret", "").strip()
    discord_webhook_url = data.get("discord_webhook_url", "").strip()

    if not all([repo_url, secret, discord_webhook_url]):
        logger.warning("API: Verify repository rejected - missing required fields")
        return jsonify({"error": "Missing required fields"}), 400

    # Extract owner and repo from URL
    repo_info = extract_repo_info_from_url(repo_url)
    if not repo_info:
        logger.warning(f"API: Verify repository rejected - invalid URL: {repo_url}")
        return jsonify({"error": "Invalid GitHub repository URL"}), 400

    owner, repo_name = repo_info

    # Fetch repository data from GitHub
    github_data = fetch_repo_data_from_github(owner, repo_name)
    if not github_data:
        logger.error(
            "API: Verify repository failed - could not fetch GitHub data for %s/%s",
            owner,
            repo_name
        )
        return jsonify({"error": "Could not fetch repository data from GitHub"}), 400

    # Get repository from database
    repo_config = get_repository_by_id(github_data["repo_id"])
    if not repo_config:
        logger.warning(
            "API: Verify repository failed - repository not found: %s (ID: %s)",
            github_data['repo_full_name'],
            github_data['repo_id']
        )
        return jsonify({"error": "Repository not found in database"}), 404

    # Verify secret and webhook URL
    if not verify_secret(secret, repo_config["secret_encrypted"]):
        logger.warning(
            "API: Verify repository failed - invalid secret for %s",
            github_data['repo_full_name']
        )
        return jsonify({"error": "Invalid secret"}), 403

    if repo_config["discord_webhook_url"] != discord_webhook_url:
        logger.warning(
            "API: Verify repository failed - invalid webhook URL for %s",
            github_data['repo_full_name']
        )
        return jsonify({"error": "Invalid Discord webhook URL"}), 403

    logger.info(
        "API: Repository verified successfully: %s (ID: %s)",
        github_data['repo_full_name'],
        github_data['repo_id']
    )
    return (
        jsonify(
            {
                "message": "Repository verified",
                "repo_id": repo_config["repo_id"],
                "repo_full_name": repo_config["repo_full_name"],
                "enabled_events": repo_config["enabled_events"],
            }
        ),
        200,
    )


@app.route("/api/repositories/<int:repo_id>", methods=["PUT"])
@require_api_key_or_csrf
def api_update_repository(repo_id):  # pylint: disable=too-many-return-statements
    """
    Updates repository configuration.

    Expected JSON payload:
    {
        "old_secret": "current_secret",
        "new_secret": "new_secret" (optional),
        "discord_webhook_url": "new_webhook_url" (optional),
        "enabled_events": "star,watch"
    }
    """
    logger.info(
        f"API: Update repository request for repo_id {repo_id} from {request.remote_addr}"
    )
    data = request.get_json(silent=True)
    if not data:
        logger.warning(
            f"API: Update repository {repo_id} rejected - missing JSON payload"
        )
        return jsonify({"error": "Missing JSON payload"}), 400

    old_secret = data.get("old_secret", "").strip()
    enabled_events = data.get("enabled_events", "").strip()

    if not old_secret or not enabled_events:
        logger.warning(
            f"API: Update repository {repo_id} rejected - missing required fields"
        )
        return jsonify({"error": "Missing required fields"}), 400

    # Validate enabled events
    events = enabled_events.split(",")
    valid_events = {"star", "watch"}
    if not all(event in valid_events for event in events):
        logger.warning(
            f"API: Update repository {repo_id} rejected - invalid event types: {enabled_events}"
        )
        return jsonify({"error": "Invalid event types"}), 400

    # Get repository from database
    repo_config = get_repository_by_id(repo_id)
    if not repo_config:
        logger.warning(
            f"API: Update repository failed - repository not found: {repo_id}"
        )
        return jsonify({"error": "Repository not found"}), 404

    # Verify old secret
    if not verify_secret(old_secret, repo_config["secret_encrypted"]):
        logger.warning(f"API: Update repository {repo_id} failed - invalid secret")
        return jsonify({"error": "Invalid secret"}), 403

    # Prepare updates
    updates = []
    params = []
    changes = []

    new_secret = data.get("new_secret", "").strip()
    if new_secret:
        updates.append("secret_encrypted = ?")
        params.append(encrypt_secret(new_secret))
        changes.append("secret")

    discord_webhook_url = data.get("discord_webhook_url", "").strip()
    if discord_webhook_url:
        if not verify_discord_webhook(discord_webhook_url):
            logger.warning(
                f"API: Update repository {repo_id} failed - invalid Discord webhook"
            )
            return jsonify({"error": "Discord webhook URL is invalid or inactive"}), 400
        updates.append("discord_webhook_url = ?")
        params.append(discord_webhook_url)
        changes.append("webhook URL")

    updates.append("enabled_events = ?")
    params.append(enabled_events)
    changes.append("events")

    updates.append("updated_at = CURRENT_TIMESTAMP")

    params.append(repo_id)

    # Update database
    db = get_db()
    try:
        db.execute(
            f"UPDATE repositories SET {', '.join(updates)} WHERE repo_id = ?", params
        )
        logger.info(
            "API: Repository %s (%s) updated successfully - Changed: %s",
            repo_id,
            repo_config['repo_full_name'],
            ', '.join(changes)
        )
        return jsonify({"message": "Repository updated successfully"}), 200
    except sqlite3.Error as e:
        logger.error(
            "API: Database error updating repository %s: %s",
            repo_id,
            e
        )
        return jsonify({"error": f"Database error: {e}"}), 500


@app.route("/api/repositories/<int:repo_id>", methods=["DELETE"])
@require_api_key_or_csrf
def api_delete_repository(repo_id):
    """
    Deletes a repository configuration.

    Expected JSON payload:
    {
        "secret": "webhook_secret"
    }
    """
    logger.info(
        f"API: Delete repository request for repo_id {repo_id} from {request.remote_addr}"
    )
    data = request.get_json(silent=True)
    if not data:
        logger.warning(
            f"API: Delete repository {repo_id} rejected - missing JSON payload"
        )
        return jsonify({"error": "Missing JSON payload"}), 400

    secret = data.get("secret", "").strip()
    if not secret:
        logger.warning(f"API: Delete repository {repo_id} rejected - missing secret")
        return jsonify({"error": "Missing secret"}), 400

    # Get repository from database
    repo_config = get_repository_by_id(repo_id)
    if not repo_config:
        logger.warning(
            f"API: Delete repository failed - repository not found: {repo_id}"
        )
        return jsonify({"error": "Repository not found"}), 404

    # Verify secret
    if not verify_secret(secret, repo_config["secret_encrypted"]):
        logger.warning(f"API: Delete repository {repo_id} failed - invalid secret")
        return jsonify({"error": "Invalid secret"}), 403

    # Delete from database
    db = get_db()
    try:
        db.execute("DELETE FROM repositories WHERE repo_id = ?", (repo_id,))
        logger.info(
            f"API: Repository {repo_id} ({repo_config['repo_full_name']}) deleted successfully"
        )
        return jsonify({"message": "Repository deleted successfully"}), 200
    except sqlite3.Error as e:
        logger.error(f"API: Database error deleting repository {repo_id}: {e}")
        return jsonify({"error": f"Database error: {e}"}), 500


# ============================================================================
# Admin Panel Routes
# ============================================================================


@app.route("/admin", methods=["GET"])
def admin_page():
    """
    Serves the admin panel page.
    """
    logger.debug(f"Admin page accessed from {request.remote_addr}")
    return render_template("admin.html")


@app.route("/admin/api/login", methods=["POST"])
def admin_login():
    """
    Authenticates admin user with password.
    """
    data = request.get_json()
    password = data.get("password")

    if not password:
        logger.warning(
            "Admin login failed: no password provided from %s",
            request.remote_addr
        )
        return jsonify({"error": "Password required"}), 400

    if verify_admin_password(password):
        session["admin_authenticated"] = True
        session["admin_login_time"] = int(time.time())
        session.permanent = True  # Use Flask's permanent session (31 days by default)
        logger.info("Admin login successful from %s", request.remote_addr)
        return jsonify({"message": "Login successful"}), 200

    logger.warning("Admin login failed: invalid password from %s", request.remote_addr)
    return jsonify({"error": "Invalid password"}), 401


@app.route("/admin/api/logout", methods=["POST"])
def admin_logout():
    """
    Logs out admin user.
    """
    session.pop("admin_authenticated", None)
    session.pop("admin_login_time", None)
    logger.info("Admin logout from %s", request.remote_addr)
    return jsonify({"message": "Logged out successfully"}), 200


@app.route("/admin/api/keys", methods=["GET"])
@require_admin_auth
def admin_list_keys():
    """
    Lists all API keys (without sensitive data).
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT id, name, created_at, last_used, is_active, permissions, rate_limit, is_admin_key
        FROM api_keys
        ORDER BY created_at DESC
        """
    )
    keys = cursor.fetchall()

    logger.info("Admin: Listed %s API keys", len(keys))
    return jsonify(
        {
            "keys": [
                {
                    "id": key["id"],
                    "name": key["name"],
                    "created_at": key["created_at"],
                    "last_used": key["last_used"],
                    "is_active": bool(key["is_active"]),
                    "permissions": key["permissions"] if key["permissions"] is not None else 0,
                    "rate_limit": key["rate_limit"] if key["rate_limit"] is not None else 100,
                    "is_admin_key": bool(key["is_admin_key"] if key["is_admin_key"] is not None else 0),
                }
                for key in keys
            ]
        }
    ), 200


@app.route("/admin/api/keys", methods=["POST"])
@require_admin_auth
def admin_create_key():
    """
    Creates a new API key with granular permissions and rate limit.
    Can also create admin keys with full access.
    """
    data = request.get_json()
    name = data.get("name")
    permissions = data.get("permissions", 0)
    rate_limit = data.get("rate_limit", 100)
    is_admin_key = data.get("is_admin_key", False)

    if not name:
        return jsonify({"error": "Name required"}), 400
    
    # Validate name: max 16 characters, alphanumeric, spaces, hyphens, and underscores only
    if len(name) > 16:
        return jsonify({"error": "Name must be 16 characters or less"}), 400
    
    if not name.replace('-', '').replace('_', '').replace(' ', '').isalnum():
        return jsonify({"error": "Name can only contain letters, numbers, spaces, hyphens, and underscores"}), 400

    # Admin keys have unrestricted access and ignore permissions/rate_limit
    if is_admin_key:
        permissions_value = -1  # Use -1 for full access
        rate_limit = 0  # Unlimited for admin keys
        logger.info("Creating admin API key (unrestricted access)")
    else:
        # Validate bitmap integer
        try:
            permissions_value = int(permissions)
            # Ensure at least one permission is set (bitmap must be > 0)
            if permissions_value <= 0:
                return jsonify({"error": "At least one permission must be selected (permissions cannot be 0)"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Permissions must be an integer bitmap"}), 400
        # Validate rate limit (0 means unlimited)
        try:
            rate_limit = int(rate_limit)
            if rate_limit < 0 or rate_limit > 1000:
                return jsonify({"error": "Rate limit must be between 0 (unlimited) and 1000"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Rate limit must be a valid number"}), 400

    # Generate a new API key
    api_key = secrets.token_urlsafe(32)
    key_hash = hash_api_key(api_key)

    # Store in database
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO api_keys (key_hash, name, permissions, rate_limit, is_admin_key) VALUES (?, ?, ?, ?, ?)",
            (key_hash, name, permissions_value, rate_limit, 1 if is_admin_key else 0)
        )
        key_id = cursor.lastrowid
        logger.info("Admin: Created new %sAPI key (ID: %s, Name: %s, Permissions: %s, Rate limit: %s)", 
                   "admin " if is_admin_key else "", key_id, name, permissions_value, rate_limit)

        # Return the plaintext key (only time it's shown)
        return jsonify(
            {
                "message": "API key created successfully",
                "api_key": api_key,
                "id": key_id,
                "name": name,
                "permissions": permissions_value,
                "rate_limit": rate_limit,
                "is_admin_key": is_admin_key
            }
        ), 201
    except sqlite3.Error as e:
        logger.error("Admin: Database error creating API key: %s", e)
        return jsonify({"error": f"Database error: {e}"}), 500


@app.route("/admin/api/keys/<int:key_id>", methods=["DELETE"])
@require_admin_auth
def admin_delete_key(key_id):
    """
    Deletes an API key.
    """
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute("SELECT name FROM api_keys WHERE id = ?", (key_id,))
        key = cursor.fetchone()

        if not key:
            return jsonify({"error": "API key not found"}), 404

        db.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        logger.info("Admin: Deleted API key (ID: %s, Name: %s)", key_id, key["name"])
        return jsonify({"message": "API key deleted successfully"}), 200
    except sqlite3.Error as e:
        logger.error("Admin: Database error deleting API key %s: %s", key_id, e)
        return jsonify({"error": f"Database error: {e}"}), 500


@app.route("/admin/api/keys/<int:key_id>/toggle", methods=["POST"])
@require_admin_auth
def admin_toggle_key(key_id):
    """
    Toggles an API key between active and inactive.
    """
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute(
            "SELECT name, is_active FROM api_keys WHERE id = ?",
            (key_id,)
        )
        key = cursor.fetchone()

        if not key:
            return jsonify({"error": "API key not found"}), 404

        new_status = 0 if key["is_active"] else 1
        db.execute(
            "UPDATE api_keys SET is_active = ? WHERE id = ?",
            (new_status, key_id)
        )

        status_text = "activated" if new_status else "deactivated"
        logger.info(
            "Admin: %s API key (ID: %s, Name: %s)",
            status_text.capitalize(),
            key_id,
            key["name"]
        )
        return jsonify(
            {
                "message": f"API key {status_text} successfully",
                "is_active": bool(new_status)
            }
        ), 200
    except sqlite3.Error as e:
        logger.error("Admin: Database error toggling API key %s: %s", key_id, e)
        return jsonify({"error": f"Database error: {e}"}), 500


@app.route("/admin/api/keys/<int:key_id>", methods=["PATCH"])
@require_admin_auth
def admin_update_key(key_id):
    """
    Updates an API key's permissions and/or rate limit.
    Note: Admin keys cannot have their permissions or rate limits changed.
    """
    data = request.get_json()
    permissions = data.get("permissions")
    rate_limit = data.get("rate_limit")
    
    if permissions is None and rate_limit is None:
        return jsonify({"error": "At least one field (permissions or rate_limit) required"}), 400
    
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute("SELECT name, is_admin_key FROM api_keys WHERE id = ?", (key_id,))
        key = cursor.fetchone()
        
        if not key:
            return jsonify({"error": "API key not found"}), 404
        
        # Prevent modification of admin keys
        if key["is_admin_key"]:
            return jsonify({"error": "Admin keys cannot be modified. Create a new key instead."}), 400
        
        updates = []
        values = []
        
        if permissions is not None:
            # Validate bitmap integer
            try:
                permissions_value = int(permissions)
                # Ensure at least one permission is set (bitmap must be > 0)
                if permissions_value <= 0:
                    return jsonify({"error": "At least one permission must be selected (permissions cannot be 0)"}), 400
                updates.append("permissions = ?")
                values.append(permissions_value)
            except (ValueError, TypeError):
                return jsonify({"error": "Permissions must be an integer bitmap"}), 400
        
        if rate_limit is not None:
            # Validate rate limit (0 means unlimited)
            try:
                rate_limit = int(rate_limit)
                if rate_limit < 0 or rate_limit > 1000:
                    return jsonify({"error": "Rate limit must be between 0 (unlimited) and 1000"}), 400
            except (ValueError, TypeError):
                return jsonify({"error": "Rate limit must be a valid number"}), 400
            updates.append("rate_limit = ?")
            values.append(rate_limit)
        
        values.append(key_id)
        query = f"UPDATE api_keys SET {', '.join(updates)} WHERE id = ?"
        
        db.execute(query, tuple(values))
        
        logger.info("Admin: Updated API key (ID: %s, Name: %s)", key_id, key["name"])
        return jsonify({"message": "API key updated successfully"}), 200
    except sqlite3.Error as e:
        logger.error("Admin: Database error updating API key %s: %s", key_id, e)
        return jsonify({"error": f"Database error: {e}"}), 500


@app.route("/admin/api/keys/bulk", methods=["POST"])
@require_admin_auth
def admin_bulk_action():
    """
    Performs bulk actions on multiple API keys.
    Actions: activate, deactivate, delete
    """
    data = request.get_json()
    action = data.get("action")
    key_ids = data.get("key_ids", [])
    
    if not action:
        return jsonify({"error": "Action required"}), 400
    
    if not key_ids or not isinstance(key_ids, list):
        return jsonify({"error": "key_ids must be a non-empty list"}), 400
    
    valid_actions = {"activate", "deactivate", "delete"}
    if action not in valid_actions:
        return jsonify({"error": f"Invalid action. Must be one of: {', '.join(valid_actions)}"}), 400
    
    db = get_db()
    try:
        cursor = db.cursor()
        
        # Validate all keys exist
        placeholders = ",".join("?" * len(key_ids))
        cursor.execute(f"SELECT id FROM api_keys WHERE id IN ({placeholders})", key_ids)
        existing_keys = [row["id"] for row in cursor.fetchall()]
        
        if len(existing_keys) != len(key_ids):
            missing = set(key_ids) - set(existing_keys)
            return jsonify({"error": f"API keys not found: {list(missing)}"}), 404
        
        # Perform action
        if action == "delete":
            db.execute(f"DELETE FROM api_keys WHERE id IN ({placeholders})", key_ids)
            message = f"Deleted {len(key_ids)} API key(s)"
        elif action == "activate":
            db.execute(f"UPDATE api_keys SET is_active = 1 WHERE id IN ({placeholders})", key_ids)
            message = f"Activated {len(key_ids)} API key(s)"
        elif action == "deactivate":
            db.execute(f"UPDATE api_keys SET is_active = 0 WHERE id IN ({placeholders})", key_ids)
            message = f"Deactivated {len(key_ids)} API key(s)"
        logger.info("Admin: Bulk %s on %d API keys: %s", action, len(key_ids), key_ids)
        return jsonify({"message": message, "affected_keys": len(key_ids)}), 200
    except sqlite3.Error as e:
        logger.error("Admin: Database error in bulk action: %s", e)
        return jsonify({"error": f"Database error: {e}"}), 500


@app.route("/admin/api/logs/list", methods=["GET"])
@require_admin_auth
def admin_list_log_files():
    """
    Lists all available log files (current and rotated).
    """
    try:
        if not os.path.exists(config.LOG_FOLDER):
            logger.warning("Admin: Log folder not found")
            return jsonify({"files": []}), 200
        
        # Get all log files in the folder
        log_files = []
        for filename in os.listdir(config.LOG_FOLDER):
            if filename.endswith('.log'):
                file_path = os.path.join(config.LOG_FOLDER, filename)
                file_stat = os.stat(file_path)
                log_files.append({
                    "name": filename,
                    "size": file_stat.st_size,
                    "modified": file_stat.st_mtime
                })
        
        # Sort by modification time (newest first)
        log_files.sort(key=lambda x: x["modified"], reverse=True)
        
        logger.info("Admin: Listed %d log files", len(log_files))
        return jsonify({"files": log_files}), 200
    except Exception as e:
        logger.error("Admin: Error listing log files: %s", e)
        return jsonify({"error": f"Error listing log files: {e}"}), 500


@app.route("/admin/api/logs", methods=["GET"])
@require_admin_auth
def admin_get_logs():
    """
    Retrieves the latest application logs.
    Returns the last 1000 lines by default.
    Query params:
    - lines: number of lines to retrieve (default: 1000, max: 1000)
    - file: log file name (default: current log file)
    """
    try:
        # Get requested log file name or use default
        log_filename = request.args.get('file', f"{config.APP_NAME}.log")
        
        # Sanitize filename to prevent directory traversal
        log_filename = os.path.basename(log_filename)
        if not log_filename.endswith('.log'):
            return jsonify({"error": "Invalid log file name"}), 400
        
        log_file_path = os.path.join(config.LOG_FOLDER, log_filename)
        
        if not os.path.exists(log_file_path):
            logger.warning("Admin: Log file not found: %s", log_filename)
            return jsonify({"logs": [], "message": "Log file not found", "loggers": []}), 200
        
        # Read the last N lines from the log file
        max_lines = request.args.get('lines', 1000, type=int)
        max_lines = min(max_lines, 1000)  # Cap at 1000 lines
        
        with open(log_file_path, 'r', encoding='utf-8') as f:
            # Read all lines and get the last N
            all_lines = f.readlines()
            logs = all_lines[-max_lines:] if len(all_lines) > max_lines else all_lines
        
        # Remove newline characters but keep the log format
        logs = [line.rstrip('\n') for line in logs]
        
        # Extract unique logger names from the logs
        loggers = set()
        for log in logs:
            # Log format: [timestamp] [PID:xxx] [LEVEL] logger_name: message
            # Extract logger_name between ] and :
            try:
                parts = log.split(']')
                if len(parts) >= 4:
                    # The logger name is after the third ] and before the :
                    logger_part = parts[3].split(':', 1)[0].strip()
                    if logger_part:
                        loggers.add(logger_part)
            except Exception:
                pass
        
        logger.debug("Admin: Retrieved %d log lines from %s with %d unique loggers", 
                    len(logs), log_filename, len(loggers))
        return jsonify({
            "logs": logs, 
            "file": log_filename,
            "loggers": sorted(list(loggers))
        }), 200
    except Exception as e:
        logger.error("Admin: Error reading logs: %s", e)
        return jsonify({"error": f"Error reading logs: {e}"}), 500


@app.route("/admin/api/logs/download", methods=["GET"])
@require_admin_auth
def admin_download_logs():
    """
    Downloads the complete log file.
    Query params:
    - file: log file name (default: current log file)
    """
    try:
        # Get requested log file name or use default
        log_filename = request.args.get('file', f"{config.APP_NAME}.log")
        
        # Sanitize filename to prevent directory traversal
        log_filename = os.path.basename(log_filename)
        if not log_filename.endswith('.log'):
            return jsonify({"error": "Invalid log file name"}), 400
        
        log_file_path = os.path.join(config.LOG_FOLDER, log_filename)
        
        if not os.path.exists(log_file_path):
            logger.warning("Admin: Log file not found for download: %s", log_filename)
            return jsonify({"error": "Log file not found"}), 404
        
        logger.info("Admin: Downloading log file: %s", log_filename)
        return send_file(
            log_file_path,
            as_attachment=True,
            download_name=f"{log_filename.replace('.log', '')}_{time.strftime('%Y%m%d_%H%M%S')}.log",
            mimetype='text/plain'
        )
    except Exception as e:
        logger.error("Admin: Error downloading logs: %s", e)
        return jsonify({"error": f"Error downloading logs: {e}"}), 500


if __name__ == "__main__":
    # When running directly (not via Gunicorn), start the periodic tasks and Flask dev server
    task_manager.start_all_tasks()
    logger.info("Periodic tasks started (direct execution mode)")
    
    logger.info(f"Starting {config.APP_NAME} v{config.APP_VERSION} on port 5000")
    app.run(host="0.0.0.0", port=5000, debug=True)

