"""
Admin Panel Routes

Admin authentication and management routes:
- /admin: Admin panel page (generates CSRF token)
- /admin/api/keys: API key management (list, create)
- /admin/api/keys/<key_id>: API key operations (delete, toggle, update)
- /admin/api/keys/bulk: Bulk API key operations
- /admin/api/logs: Log file viewing and management

Security Architecture:
- /admin/api/login: Protected by CSRF tokens to prevent external API calls
  * CSRF token generated when loading /admin page
  * Token stored in session and embedded in page meta tag
  * Login request must include valid CSRF token
  * This prevents curl/external API access while allowing browser-based login
- /admin/api/logout: Protected by session cookies
- All other /admin/api/* routes: Protected by session authentication (@require_admin_auth)

For programmatic API access with admin privileges, use an admin API key instead of sessions.
"""

import hmac
import os
import re
import secrets
import sqlite3
import sys
import time
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional

from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    render_template,
    request,
    send_file,
    session,
)

# Import config module
config_path = Path(__file__).parent.parent / ".config"
if str(config_path) not in sys.path:
    sys.path.insert(0, str(config_path))
import config  # type: ignore  # noqa: E402

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# Error message constants
ERROR_DATABASE = "Database error occurred"
ERROR_FILE_ERROR = "File operation error occurred"
ERROR_API_KEY_NOT_FOUND = "API key not found"

# These will be set by main.py when registering blueprints
logger: Optional[Any] = None
_require_admin_auth: Optional[Callable] = None  # Store the actual decorator
verify_admin_password: Optional[Callable[[str], bool]] = None
hash_api_key: Optional[Callable[[str], str]] = None
get_db: Optional[Callable[[], Any]] = None
increment_stat: Optional[Callable[[str], None]] = None
internal_server_secret: Optional[str] = None  # Secret for internal-only routes


def require_admin_auth(f):
    """Wrapper decorator that delegates to the actual decorator after initialization"""

    @wraps(f)
    def wrapper(*args, **kwargs):
        assert _require_admin_auth is not None
        return _require_admin_auth(f)(*args, **kwargs)

    return wrapper


def require_internal_secret(f):
    """
    Decorator to require the internal server secret for internal-only routes.
    This prevents external access to admin login/logout endpoints.
    Only the admin panel HTML page has access to this secret.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        # Check for internal secret in X-Internal-Secret header
        provided_secret = request.headers.get("X-Internal-Secret")

        if not provided_secret or not internal_server_secret:
            if logger:
                logger.warning(
                    f"Internal route access denied: missing secret from {request.remote_addr}"
                )
            return jsonify({"error": "Access denied"}), 403

        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(provided_secret, internal_server_secret):
            if logger:
                logger.warning(
                    f"Internal route access denied: invalid secret from {request.remote_addr}"
                )
            return jsonify({"error": "Access denied"}), 403

        return f(*args, **kwargs)

    return wrapper


def init_admin_routes(
    _logger,
    _require_admin_auth_func,
    _verify_admin_password,
    _hash_api_key,
    _get_db,
    _increment_stat=None,
    _internal_server_secret=None,
):
    """Initialize route dependencies"""
    global logger, _require_admin_auth, verify_admin_password
    global hash_api_key, get_db, increment_stat, internal_server_secret

    logger = _logger
    _require_admin_auth = _require_admin_auth_func
    verify_admin_password = _verify_admin_password
    hash_api_key = _hash_api_key
    get_db = _get_db
    increment_stat = _increment_stat
    internal_server_secret = _internal_server_secret
    increment_stat = _increment_stat


@admin_bp.route("", methods=["GET"])
def admin_page():
    """
    Serves the admin panel page with a CSRF token.
    The CSRF token protects the login endpoint from external access.

    If user has an active admin session, pass that info to the frontend
    so it can skip the login form and go straight to the dashboard.
    """
    # Generate a CSRF token for this session
    csrf_token = secrets.token_urlsafe(32)
    session["csrf_token"] = csrf_token
    session.modified = True

    # Check if user has an active admin session
    is_authenticated = session.get("admin_authenticated", False)

    if logger:
        logger.debug(
            f"Admin page accessed from {request.remote_addr}, CSRF token "
            f"generated, authenticated: {is_authenticated}"
        )

    return render_template("admin.html", csrf_token=csrf_token, is_authenticated=is_authenticated)


# Internal-only route - not documented in OpenAPI, used only by admin panel UI
@admin_bp.route("/api/login", methods=["POST"])
def admin_login():
    """
    Authenticates admin user with password.

    INTERNAL USE ONLY: This endpoint is not part of the public API documentation.
    It is used exclusively by the admin panel UI at /admin for session management.

    For API access with admin privileges, use an admin API key instead.

    Security: Protected by CSRF tokens to prevent external API access.
    """
    # Ensure dependencies are initialized
    assert verify_admin_password is not None

    # Validate request data
    data = request.get_json()
    if not data:
        if logger:
            logger.warning("Admin login failed: no JSON data from %s", request.remote_addr)
        return jsonify({"error": "Invalid request"}), 400

    # Validate CSRF token
    csrf_error = _validate_login_csrf(data)
    if csrf_error:
        return csrf_error

    # Validate password
    password = data.get("password")
    if not password:
        if logger:
            logger.warning("Admin login failed: no password provided from %s", request.remote_addr)
        return jsonify({"error": "Password required"}), 400

    # Attempt authentication
    if verify_admin_password(password):
        return _create_admin_session()

    if logger:
        logger.warning("Admin login failed: invalid password from %s", request.remote_addr)
    return jsonify({"error": "Invalid password"}), 401


def _validate_login_csrf(data):
    """
    Validate CSRF token for login request.

    Args:
        data: Request data containing csrf_token

    Returns:
        Error response if validation fails, None if valid
    """
    csrf_token = data.get("csrf_token")
    session_csrf_token = session.get("csrf_token")

    if not csrf_token or not session_csrf_token:
        if logger:
            logger.warning("Admin login failed: missing CSRF token from %s", request.remote_addr)
        return jsonify({"error": "Access denied - CSRF token missing"}), 403

    # Use constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(csrf_token, session_csrf_token):
        if logger:
            logger.warning("Admin login failed: invalid CSRF token from %s", request.remote_addr)
        return jsonify({"error": "Access denied - Invalid CSRF token"}), 403

    return None


def _create_admin_session():
    """
    Create an authenticated admin session.

    Returns:
        Response with session cookie
    """
    # Security: Regenerate session to prevent session fixation attacks
    # Store CSRF token before clearing
    old_csrf = session.get("csrf_token")

    # Clear old session data
    session.clear()

    # Restore CSRF token and set auth
    session["csrf_token"] = old_csrf
    session["admin_authenticated"] = True
    session["admin_login_time"] = int(time.time())
    session.permanent = True  # Use Flask's permanent session (31 days by default)
    session.modified = True  # Force session regeneration

    if logger:
        logger.info("Admin login successful from %s", request.remote_addr)

    # Get the session interface to access the serializer
    session_interface = current_app.session_interface

    # Create response and save the session into it so the Set-Cookie header is sent
    response = make_response(jsonify({"message": "Login successful"}), 200)
    # Persist the session cookie on the real response so browser stores it automatically
    session_interface.save_session(current_app, session, response)
    return response


# Internal-only route - not documented in OpenAPI, used only by admin panel UI
@admin_bp.route("/api/logout", methods=["POST"])
def admin_logout():
    """
    Logs out admin user.

    INTERNAL USE ONLY: This endpoint is not part of the public API documentation.
    It is used exclusively by the admin panel UI at /admin for session management.
    """
    session.pop("admin_authenticated", None)
    session.pop("admin_login_time", None)
    if logger:
        logger.info("Admin logout from %s", request.remote_addr)
    return jsonify({"message": "Logged out successfully"}), 200


@admin_bp.route("/api/permissions", methods=["GET"])
@require_admin_auth
def admin_get_permissions():
    """
    Returns the centralized permission configuration for the admin panel.
    This ensures the UI always matches the backend configuration.
    """
    return jsonify({"permissions": config.PERMISSIONS}), 200


@admin_bp.route("/api/keys", methods=["GET"])
@require_admin_auth
def admin_list_keys():
    """
    Lists all API keys (without sensitive data).
    """
    assert get_db is not None
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

    if logger:
        logger.info("Admin: Listed %s API keys", len(keys))
    return (
        jsonify(
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
                        "is_admin_key": bool(
                            key["is_admin_key"] if key["is_admin_key"] is not None else 0
                        ),
                    }
                    for key in keys
                ]
            }
        ),
        200,
    )


@admin_bp.route("/api/keys", methods=["POST"])
@require_admin_auth
def admin_create_key():  # NOSONAR
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

    # Security: Strict validation - reject potentially dangerous characters
    if not name.replace("-", "").replace("_", "").replace(" ", "").isalnum():
        return (
            jsonify(
                {
                    "error": (
                        "Name can only contain letters, numbers, spaces, "
                        "hyphens, and underscores"
                    )
                }
            ),
            400,
        )

    # Security: Prevent XSS via name field
    # Check for potential script injection patterns
    dangerous_patterns = ["<", ">", "&", '"', "'", "\\", "/", "(", ")", "{", "}", "[", "]"]
    if any(char in name for char in dangerous_patterns):
        return jsonify({"error": "Name contains invalid characters"}), 400

    # Admin keys have unrestricted access and ignore permissions/rate_limit
    if is_admin_key:
        permissions_value = -1  # Use -1 for full access
        rate_limit = 0  # Unlimited for admin keys
        if logger:
            logger.info("Creating admin API key (unrestricted access)")
    else:
        # Validate bitmap integer
        try:
            permissions_value = int(permissions)
            # Ensure at least one permission is set (bitmap must be > 0)
            if permissions_value <= 0:
                return (
                    jsonify(
                        {
                            "error": (
                                "At least one permission must be selected "
                                "(permissions cannot be 0)"
                            )
                        }
                    ),
                    400,
                )
            # Validate bitmap is within valid range
            if permissions_value > config.MAX_PERMISSION_VALUE:
                return (
                    jsonify({"error": "Invalid permissions bitmap (out of range)"}),
                    400,
                )
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
    assert hash_api_key is not None
    key_hash = hash_api_key(api_key)

    # Store in database
    assert get_db is not None
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute(
            """INSERT INTO api_keys (key_hash, name, permissions, rate_limit, is_admin_key)
            VALUES (?, ?, ?, ?, ?)""",
            (key_hash, name, permissions_value, rate_limit, 1 if is_admin_key else 0),
        )
        key_id = cursor.lastrowid

        # Increment total API keys statistic
        if increment_stat:
            increment_stat("total_api_keys")

        if logger:
            logger.info(
                "Admin: Created new %sAPI key (ID: %s, Name: %s, Permissions: %s, Rate limit: %s)",
                "admin " if is_admin_key else "",
                key_id,
                name,
                permissions_value,
                rate_limit,
            )

        # Return the plaintext key (only time it's shown)
        return (
            jsonify(
                {
                    "message": "API key created successfully",
                    "api_key": api_key,
                    "id": key_id,
                    "name": name,
                    "permissions": permissions_value,
                    "rate_limit": rate_limit,
                    "is_admin_key": is_admin_key,
                }
            ),
            201,
        )
    except sqlite3.Error as e:
        if logger:
            logger.error("Admin: Database error creating API key: %s", e)
        return jsonify({"error": ERROR_DATABASE}), 500


@admin_bp.route("/api/keys/<int:key_id>", methods=["DELETE"])
@require_admin_auth
def admin_delete_key(key_id):
    """
    Deletes an API key.
    """
    assert get_db is not None
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute("SELECT name FROM api_keys WHERE id = ?", (key_id,))
        key = cursor.fetchone()

        if not key:
            return jsonify({"error": ERROR_API_KEY_NOT_FOUND}), 404

        db.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        if logger:
            logger.info("Admin: Deleted API key (ID: %s, Name: %s)", key_id, key["name"])
        return jsonify({"message": "API key deleted successfully"}), 200
    except sqlite3.Error as e:
        if logger:
            logger.error("Admin: Database error deleting API key %s: %s", key_id, e)
        return jsonify({"error": ERROR_DATABASE}), 500


@admin_bp.route("/api/keys/<int:key_id>/toggle", methods=["POST"])
@require_admin_auth
def admin_toggle_key(key_id):
    """
    Toggles an API key between active and inactive.
    """
    assert get_db is not None
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute("SELECT name, is_active FROM api_keys WHERE id = ?", (key_id,))
        key = cursor.fetchone()

        if not key:
            return jsonify({"error": ERROR_API_KEY_NOT_FOUND}), 404

        new_status = 0 if key["is_active"] else 1
        db.execute("UPDATE api_keys SET is_active = ? WHERE id = ?", (new_status, key_id))

        status_text = "activated" if new_status else "deactivated"
        if logger:
            logger.info(
                "Admin: %s API key (ID: %s, Name: %s)",
                status_text.capitalize(),
                key_id,
                key["name"],
            )
        return (
            jsonify(
                {"message": f"API key {status_text} successfully", "is_active": bool(new_status)}
            ),
            200,
        )
    except sqlite3.Error as e:
        if logger:
            logger.error("Admin: Database error toggling API key %s: %s", key_id, e)
        return jsonify({"error": ERROR_DATABASE}), 500


@admin_bp.route("/api/keys/<int:key_id>", methods=["PATCH"])
@require_admin_auth
def admin_update_key(key_id):  # NOSONAR
    """
    Updates an API key's permissions and/or rate limit.
    Note: Admin keys cannot have their permissions or rate limits changed.
    """
    data = request.get_json()
    permissions = data.get("permissions")
    rate_limit = data.get("rate_limit")

    if permissions is None and rate_limit is None:
        return jsonify({"error": "At least one field (permissions or rate_limit) required"}), 400

    assert get_db is not None
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute("SELECT name, is_admin_key FROM api_keys WHERE id = ?", (key_id,))
        key = cursor.fetchone()

        if not key:
            return jsonify({"error": ERROR_API_KEY_NOT_FOUND}), 404

        # Prevent modification of admin keys
        if key["is_admin_key"]:
            return (
                jsonify({"error": "Admin keys cannot be modified. Create a new key instead."}),
                400,
            )

        updates = []
        values = []

        if permissions is not None:
            # Validate bitmap integer
            try:
                permissions_value = int(permissions)
                # Ensure at least one permission is set (bitmap must be > 0)
                if permissions_value <= 0:
                    return (
                        jsonify(
                            {
                                "error": (
                                    "At least one permission must be selected "
                                    "(permissions cannot be 0)"
                                )
                            }
                        ),
                        400,
                    )
                updates.append("permissions = ?")
                values.append(permissions_value)
            except (ValueError, TypeError):
                return jsonify({"error": "Permissions must be an integer bitmap"}), 400

        if rate_limit is not None:
            # Validate rate limit (0 means unlimited)
            try:
                rate_limit = int(rate_limit)
                if rate_limit < 0 or rate_limit > 1000:
                    return (
                        jsonify({"error": "Rate limit must be between 0 (unlimited) and 1000"}),
                        400,
                    )
            except (ValueError, TypeError):
                return jsonify({"error": "Rate limit must be a valid number"}), 400
            updates.append("rate_limit = ?")
            values.append(rate_limit)

        values.append(key_id)
        # Security: Use pre-defined allowed columns only to prevent SQL injection
        allowed_updates = {"permissions": "permissions = ?", "rate_limit": "rate_limit = ?"}
        safe_updates = []
        for update in updates:
            column = update.split(" = ")[0]
            if column in allowed_updates:
                safe_updates.append(allowed_updates[column])

        query = f"UPDATE api_keys SET {', '.join(safe_updates)} WHERE id = ?"
        db.execute(query, tuple(values))

        if logger:
            logger.info("Admin: Updated API key (ID: %s, Name: %s)", key_id, key["name"])
        return jsonify({"message": "API key updated successfully"}), 200
    except sqlite3.Error as e:
        if logger:
            logger.error("Admin: Database error updating API key %s: %s", key_id, e)
        return jsonify({"error": ERROR_DATABASE}), 500


@admin_bp.route("/api/keys/bulk", methods=["POST"])
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
        return (
            jsonify({"error": f"Invalid action. Must be one of: {', '.join(valid_actions)}"}),
            400,
        )

    assert get_db is not None
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
        message = ""  # Initialize message to avoid unbound variable warning
        if action == "delete":
            db.execute(f"DELETE FROM api_keys WHERE id IN ({placeholders})", key_ids)
            message = f"Deleted {len(key_ids)} API key(s)"
        elif action == "activate":
            db.execute(f"UPDATE api_keys SET is_active = 1 WHERE id IN ({placeholders})", key_ids)
            message = f"Activated {len(key_ids)} API key(s)"
        elif action == "deactivate":
            db.execute(f"UPDATE api_keys SET is_active = 0 WHERE id IN ({placeholders})", key_ids)
            message = f"Deactivated {len(key_ids)} API key(s)"
        if logger:
            logger.info("Admin: Bulk %s on %d API keys: %s", action, len(key_ids), key_ids)
        return jsonify({"message": message, "affected_keys": len(key_ids)}), 200
    except sqlite3.Error as e:
        if logger:
            logger.error("Admin: Database error in bulk action: %s", e)
        return jsonify({"error": ERROR_DATABASE}), 500


@admin_bp.route("/api/logs/list", methods=["GET"])
@require_admin_auth
def admin_list_log_files():
    """
    Lists all available log files (current and rotated).
    """
    # config is imported at module level

    try:
        if not os.path.exists(config.LOG_FOLDER):
            if logger:
                logger.warning("Admin: Log folder not found")
            return jsonify({"files": []}), 200

        # Get all log files in the folder
        log_files = []
        for filename in os.listdir(config.LOG_FOLDER):
            if filename.endswith(".log"):
                file_path = os.path.join(config.LOG_FOLDER, filename)
                file_stat = os.stat(file_path)
                log_files.append(
                    {"name": filename, "size": file_stat.st_size, "modified": file_stat.st_mtime}
                )

        # Sort by modification time (newest first)
        log_files.sort(key=lambda x: x["modified"], reverse=True)

        if logger:
            logger.info("Admin: Listed %d log files", len(log_files))
        return jsonify({"files": log_files}), 200
    except Exception as e:
        if logger:
            logger.error("Admin: Error listing log files: %s", e)
        return jsonify({"error": ERROR_FILE_ERROR}), 500


@admin_bp.route("/api/logs", methods=["GET"])
@require_admin_auth
def admin_get_logs():  # NOSONAR
    """
    Retrieves the latest application logs in reverse order (newest first).
    Returns the last 1000 lines by default.
    Query params:
    - lines: number of lines to retrieve (default: 1000, max: 10000)
    - file: log file name (default: current log file)
    """
    # config is imported at module level

    try:
        # Get requested log file name or use default
        log_filename = request.args.get("file", f"{config.APP_NAME}.log")

        # Security: Strict validation to prevent directory traversal attacks
        # Only allow alphanumeric, hyphens, underscores, and .log extension
        if not re.match(r"^[a-zA-Z0-9_-]+\.log$", log_filename):
            if logger:
                logger.warning("Admin: Invalid log file name format: %s", log_filename)
            return jsonify({"error": "Invalid log file name"}), 400

        log_file_path = os.path.join(config.LOG_FOLDER, log_filename)

        if not os.path.exists(log_file_path):
            if logger:
                logger.warning("Admin: Log file not found: %s", log_filename)
            return jsonify({"logs": [], "message": "Log file not found", "loggers": []}), 200

        # Read the last N lines from the log file
        max_lines = request.args.get("lines", 1000, type=int)
        max_lines = min(max(max_lines, 1), 10000)  # Clamp between 1 and 10000 lines

        with open(log_file_path, "r", encoding="utf-8") as f:
            # Read all lines and get the last N
            all_lines = f.readlines()
            logs = all_lines[-max_lines:] if len(all_lines) > max_lines else all_lines

        # Remove newline characters but keep the log format
        logs = [line.rstrip("\n") for line in logs]

        # Reverse the order so newest logs are first
        logs.reverse()

        # Extract unique logger names from the logs
        loggers = set()
        for log in logs:
            # Log format: [timestamp] [PID:xxx] [LEVEL] logger_name: message
            # Extract logger_name between ] and :
            try:
                parts = log.split("]")
                if len(parts) >= 4:
                    # The logger name is after the third ] and before the :
                    logger_part = parts[3].split(":", 1)[0].strip()
                    if logger_part:
                        loggers.add(logger_part)
            except Exception:
                pass

        if logger:
            logger.debug(
                "Admin: Retrieved %d log lines from %s with %d unique loggers",
                len(logs),
                log_filename,
                len(loggers),
            )
        return (
            jsonify(
                {
                    "logs": logs,
                    "file": log_filename,
                    "lines_returned": len(logs),
                    "lines_requested": max_lines,
                    "loggers": sorted(loggers),
                    "note": "Logs are returned in reverse chronological order (newest first)",
                }
            ),
            200,
        )
    except Exception as e:
        if logger:
            logger.error("Admin: Error reading logs: %s", e)
        return jsonify({"error": ERROR_FILE_ERROR}), 500


@admin_bp.route("/api/logs/download", methods=["GET"])
@require_admin_auth
def admin_download_logs():
    """
    Downloads the complete log file.
    Query params:
    - file: log file name (default: current log file)
    """
    # config is imported at module level

    try:
        # Get requested log file name or use default
        log_filename = request.args.get("file", f"{config.APP_NAME}.log")

        # Security: Strict validation to prevent directory traversal attacks
        # Only allow alphanumeric, hyphens, underscores, and .log extension
        if not re.match(r"^[a-zA-Z0-9_-]+\.log$", log_filename):
            if logger:
                logger.warning("Admin: Invalid log file name format for download: %s", log_filename)
            return jsonify({"error": "Invalid log file name"}), 400

        log_file_path = os.path.join(config.LOG_FOLDER, log_filename)

        if not os.path.exists(log_file_path):
            if logger:
                logger.warning("Admin: Log file not found for download: %s", log_filename)
            return jsonify({"error": "Log file not found"}), 404

        if logger:
            logger.info("Admin: Downloading log file: %s", log_filename)
        download_name = f"{log_filename.replace('.log', '')}_{time.strftime('%Y%m%d_%H%M%S')}.log"
        return send_file(
            log_file_path,
            as_attachment=True,
            download_name=download_name,
            mimetype="text/plain",
        )
    except Exception as e:
        if logger:
            logger.error("Admin: Error downloading logs: %s", e)
        return jsonify({"error": ERROR_FILE_ERROR}), 500
