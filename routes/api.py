"""
API Routes for Frontend

Frontend API routes for repository management:
- /api/generate-secret: Generate webhook secrets
- /api/repositories: Add/update/delete repository
- /api/repositories/verify: Verify repository credentials
- /api/events: List all available event types
- /api/permissions: List all available permissions
- /api/permissions/calculate: Calculate permission bitmap from list
- /api/permissions/decode: Decode permission bitmap to list
"""

import secrets
import sqlite3
import sys
import time
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional

from flask import Blueprint, g, jsonify, request, session

# Import config module
config_path = Path(__file__).parent.parent / ".config"
if str(config_path) not in sys.path:
    sys.path.insert(0, str(config_path))
import config  # type: ignore  # noqa: E402

api_bp = Blueprint("api", __name__, url_prefix="/api")

# Error message constants
ERROR_DATABASE = "Database error occurred"
ERROR_MISSING_JSON = "Missing JSON payload"
ERROR_MISSING_FIELDS = "Missing required fields"
ERROR_INVALID_SECRET = "Invalid secret"
ERROR_INVALID_DISCORD_WEBHOOK = "Invalid Discord webhook URL"
ERROR_PERMISSION_NOT_INITIALIZED = "Permission system not initialized"

# These will be set by main.py when registering blueprints
logger: Optional[Any] = None
_require_api_key_or_csrf: Optional[Callable] = None  # Store the actual decorator
github_handler: Optional[Any] = None
discord_handler: Optional[Any] = None
encrypt_secret: Optional[Callable[[str], bytes]] = None
get_db: Optional[Callable[[], Any]] = None
get_repository_by_id: Optional[Callable[[int], Optional[dict[str, Any]]]] = None
verify_secret: Optional[Callable[[bytes, str], bool]] = None
bitmap_handler: Optional[Any] = None  # Add bitmap_handler for permission calculations
increment_stat: Optional[Callable[[str], None]] = None
get_all_stats: Optional[Callable] = None
get_top_users: Optional[Callable] = None


def require_api_key_or_csrf(f):
    """Wrapper decorator that delegates to the actual decorator after initialization"""

    @wraps(f)
    def wrapper(*args, **kwargs):
        assert _require_api_key_or_csrf is not None
        return _require_api_key_or_csrf(f)(*args, **kwargs)

    return wrapper


def init_api_routes(
    _logger,
    _require_api_key_or_csrf_func,
    _github_handler,
    _discord_handler,
    _encrypt_secret,
    _get_db,
    _get_repository_by_id,
    _verify_secret,
    _bitmap_handler,
    _increment_stat=None,
    _get_all_stats=None,
    _get_top_users=None,
):
    """Initialize route dependencies"""
    global logger, _require_api_key_or_csrf, github_handler
    global discord_handler, encrypt_secret
    global get_db, get_repository_by_id, verify_secret, bitmap_handler, increment_stat
    global get_all_stats, get_top_users

    logger = _logger
    _require_api_key_or_csrf = _require_api_key_or_csrf_func
    github_handler = _github_handler
    discord_handler = _discord_handler
    encrypt_secret = _encrypt_secret
    get_db = _get_db
    get_repository_by_id = _get_repository_by_id
    verify_secret = _verify_secret
    bitmap_handler = _bitmap_handler
    increment_stat = _increment_stat
    get_all_stats = _get_all_stats
    get_top_users = _get_top_users


def check_permission(permission_name: str):
    """
    Check if the current API key has the required permission.
    CSRF tokens and admin keys bypass permission checks.

    Args:
        permission_name: The permission to check (e.g., "generate-secret", "stats")

    Returns:
        tuple: (error_response, status_code) if permission denied, None if allowed
    """
    # CSRF tokens bypass permission checks (only used by authenticated web UI)
    # Check if this request is CSRF-authenticated (from frontend)
    if getattr(g, "is_csrf_auth", False):
        return None
    
    # API key authentication requires permission checks
    # Check if this is an API key request by verifying if api_key_id was set
    if not hasattr(g, "api_key_id"):
        # No authentication at all - this shouldn't happen as decorator should block
        return None

    # Admin keys have all permissions
    if getattr(g, "is_admin_key", False):
        return None

    # Check if the API key has the required permission
    permissions_bitmap = getattr(g, "api_key_permissions", 0)
    if not bitmap_handler.check_key_in_bitkey(permission_name, permissions_bitmap):  # type: ignore
        if logger:
            logger.warning(
                "API route access denied: API key ID %s lacks '%s' permission",
                g.api_key_id,
                permission_name,
            )
        return (
            jsonify({"error": f"Insufficient permissions (requires '{permission_name}')"}),
            403,
        )

    return None


@api_bp.route("/generate-secret", methods=["GET"])
@require_api_key_or_csrf
def api_generate_secret():
    """
    Generates a cryptographically secure random secret.
    """
    # Check permission
    perm_check = check_permission("generate-secret")
    if perm_check:
        return perm_check

    if logger:
        logger.debug(f"Secret generation requested from {request.remote_addr}")
    secret = secrets.token_urlsafe(32)
    return jsonify({"secret": secret}), 200


@api_bp.route("/repositories", methods=["POST", "PATCH", "DELETE"])
@require_api_key_or_csrf
def api_manage_repository():  # pylint: disable=too-many-return-statements # NOSONAR
    """
    Manages repository configuration (add, update, or delete).

    POST - Adds a new repository:
    {
        "repo_url": "https://github.com/owner/repo",
        "secret": "webhook_secret",
        "discord_webhook_url": "https://discord.com/api/webhooks/...",
        "enabled_events": "star,watch"
    }

    PATCH - Updates repository configuration:
    {
        "repository_name": "owner/repo",
        "discord_webhook_url": "current_discord_webhook_url" (required for authentication),
        "new_secret": "new_secret" (optional - only if changing secret),
        "new_discord_webhook_url": "new_webhook_url" (optional - only if changing webhook),
        "enabled_events": "star,watch" (optional - defaults to current if not provided)
    }

    DELETE - Deletes a repository configuration:
    {
        "repository_name": "owner/repo",
        "discord_webhook_url": "https://discord.com/api/webhooks/..."
    }
    """
    # Check permissions based on the HTTP method
    if request.method == "POST":
        perm_check = check_permission("repositories-add")
        if perm_check:
            return perm_check
    elif request.method == "PATCH":
        perm_check = check_permission("repositories-update")
        if perm_check:
            return perm_check
    elif request.method == "DELETE":
        perm_check = check_permission("repositories-delete")
        if perm_check:
            return perm_check

    # Ensure dependencies are initialized
    assert get_db is not None
    assert github_handler is not None
    assert discord_handler is not None
    assert encrypt_secret is not None

    if request.method == "POST":
        if logger:
            logger.info(f"API: Add repository request from {request.remote_addr}")
        data = request.get_json(silent=True)
        if not data:
            if logger:
                logger.warning("API: Add repository rejected - missing JSON payload")
            return jsonify({"error": ERROR_MISSING_JSON}), 400

        repo_url = data.get("repo_url", "").strip()
        secret = data.get("secret", "").strip()
        discord_webhook_url = data.get("discord_webhook_url", "").strip()
        enabled_events = data.get("enabled_events", "").strip()

        # Security: Validate input lengths to prevent DoS
        if (
            len(repo_url) > 500
            or len(secret) > 500
            or len(discord_webhook_url) > 500
            or len(enabled_events) > 100
        ):
            if logger:
                logger.warning("API: Add repository rejected - input too long")
            return jsonify({"error": "Input values exceed maximum allowed length"}), 400

        # Validate inputs
        if not all([repo_url, secret, discord_webhook_url, enabled_events]):
            if logger:
                logger.warning("API: Add repository rejected - missing required fields")
            return jsonify({"error": ERROR_MISSING_FIELDS}), 400

        # Validate enabled events
        events = enabled_events.split(",")
        valid_events = {"star", "watch"}
        if not all(event in valid_events for event in events):
            if logger:
                logger.warning(
                    f"API: Add repository rejected - invalid event types: {enabled_events}"
                )
            return (
                jsonify({"error": "Invalid event types. Must be 'star' and/or 'watch'"}),
                400,
            )

        # Extract owner and repo from URL
        repo_info = github_handler.extract_repo_info_from_url(repo_url)
        if not repo_info:
            if logger:
                logger.warning(f"API: Add repository rejected - invalid URL: {repo_url}")
            return jsonify({"error": "Invalid GitHub repository URL"}), 400

        owner, repo_name = repo_info

        # Fetch repository data from GitHub
        github_data = github_handler.fetch_repo_data(owner, repo_name)
        if not github_data:
            if logger:
                logger.error(f"API: Failed to fetch GitHub data for {owner}/{repo_name}")
            return (
                jsonify(
                    {"error": "Could not fetch repository data from GitHub. Please check the URL."}
                ),
                400,
            )

        # Verify Discord webhook
        if not discord_handler.verify_webhook(discord_webhook_url):
            if logger:
                logger.warning(
                    (
                        f"API: Add repository rejected - invalid Discord webhook "
                        f"for {owner}/{repo_name}"
                    )
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

            # Increment total repositories statistic
            if increment_stat:
                increment_stat("total_repositories")

            if logger:
                logger.info(
                    "API: Repository added successfully: %s (ID: %s) - Events: %s",
                    github_data["repo_full_name"],
                    github_data["repo_id"],
                    enabled_events,
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
            if logger:
                logger.warning(
                    "API: Repository already exists: %s (ID: %s)",
                    github_data["repo_full_name"],
                    github_data["repo_id"],
                )
            return jsonify({"error": "Repository already exists in the database"}), 409
        except sqlite3.Error as e:
            if logger:
                logger.error(
                    "API: Database error adding repository %s: %s", github_data["repo_full_name"], e
                )
            return jsonify({"error": ERROR_DATABASE}), 500

    elif request.method == "PATCH":
        if logger:
            logger.info(f"API: Update repository request from {request.remote_addr}")
        data = request.get_json(silent=True)
        if not data:
            if logger:
                logger.warning("API: Update repository rejected - missing JSON payload")
            return jsonify({"error": ERROR_MISSING_JSON}), 400

        repository_name = data.get("repository_name", "").strip()
        discord_webhook_url = data.get("discord_webhook_url", "").strip()

        if not repository_name or not discord_webhook_url:
            if logger:
                logger.warning(
                    "API: Update repository rejected - missing required fields "
                    "(repository_name, discord_webhook_url)"
                )
            return jsonify({"error": ERROR_MISSING_FIELDS}), 400

        # Get repository from database by name
        db = get_db()
        repo_config = db.execute(
            "SELECT * FROM repositories WHERE repo_full_name = ?", (repository_name,)
        ).fetchone()

        if not repo_config:
            if logger:
                logger.warning(
                    f"API: Update repository failed - repository not found: {repository_name}"
                )
            return jsonify({"error": "Repository not found"}), 404

        # Verify Discord webhook URL for authentication
        if repo_config["discord_webhook_url"] != discord_webhook_url:
            if logger:
                logger.warning(
                    f"API: Update repository {repository_name} failed - invalid Discord webhook URL"
                )
            return jsonify({"error": ERROR_INVALID_DISCORD_WEBHOOK}), 403

        # Prepare updates
        updates = []
        params = []
        changes = []

        new_secret = data.get("new_secret", "").strip()
        if new_secret:
            updates.append("secret_encrypted = ?")
            params.append(encrypt_secret(new_secret))
            changes.append("secret")

        new_discord_webhook_url = data.get("new_discord_webhook_url", "").strip()
        if new_discord_webhook_url:
            if not discord_handler.verify_webhook(new_discord_webhook_url):
                if logger:
                    logger.warning(
                        (
                            f"API: Update repository {repository_name} failed - "
                            f"invalid new Discord webhook"
                        )
                    )
                return jsonify({"error": "New Discord webhook URL is invalid or inactive"}), 400
            updates.append("discord_webhook_url = ?")
            params.append(new_discord_webhook_url)
            changes.append("webhook URL")

        enabled_events = data.get("enabled_events", "").strip()
        if enabled_events:
            # Validate enabled events
            events = enabled_events.split(",")
            valid_events = {"star", "watch"}
            if not all(event in valid_events for event in events):
                if logger:
                    logger.warning(
                        f"API: Update repository rejected - invalid event types: {enabled_events}"
                    )
                return jsonify({"error": "Invalid event types"}), 400
            updates.append("enabled_events = ?")
            params.append(enabled_events)
            changes.append("events")

        # Check if any updates were requested
        if not updates:
            if logger:
                logger.warning(
                    f"API: Update repository {repository_name} rejected - no updates provided"
                )
            return jsonify({"error": "No updates provided"}), 400

        # Security: Use pre-defined allowed columns only to prevent SQL injection
        allowed_columns = {
            "secret_encrypted": "secret_encrypted = ?",
            "discord_webhook_url": "discord_webhook_url = ?",
            "enabled_events": "enabled_events = ?",
            "updated_at": "updated_at = CURRENT_TIMESTAMP",
        }

        safe_updates = []
        for update in updates:
            column = update.split(" = ")[0]
            if column in allowed_columns:
                safe_updates.append(allowed_columns[column])

        params.append(repo_config["repo_id"])

        # Update database
        try:
            db.execute(
                f"UPDATE repositories SET {', '.join(safe_updates)} WHERE repo_id = ?", params
            )
            if logger:
                logger.info(
                    "API: Repository %s (ID: %s) updated successfully - Changed: %s",
                    repository_name,
                    repo_config["repo_id"],
                    ", ".join(changes),
                )
            return jsonify({"message": "Repository updated successfully"}), 200
        except sqlite3.Error as e:
            if logger:
                logger.error("API: Database error updating repository %s: %s", repository_name, e)
            return jsonify({"error": ERROR_DATABASE}), 500

    else:  # DELETE
        if logger:
            logger.info(f"API: Delete repository request from {request.remote_addr}")
        data = request.get_json(silent=True)
        if not data:
            if logger:
                logger.warning("API: Delete repository rejected - missing JSON payload")
            return jsonify({"error": ERROR_MISSING_JSON}), 400

        repository_name = data.get("repository_name", "").strip()
        discord_webhook_url = data.get("discord_webhook_url", "").strip()

        if not repository_name or not discord_webhook_url:
            if logger:
                logger.warning("API: Delete repository rejected - missing required fields")
            return jsonify({"error": ERROR_MISSING_FIELDS}), 400

        # Get repository from database by name
        db = get_db()
        repo_config = db.execute(
            "SELECT * FROM repositories WHERE repo_full_name = ?", (repository_name,)
        ).fetchone()

        if not repo_config:
            if logger:
                logger.warning(
                    f"API: Delete repository failed - repository not found: {repository_name}"
                )
            return jsonify({"error": "Repository not found"}), 404

        # Verify Discord webhook URL matches
        if repo_config["discord_webhook_url"] != discord_webhook_url:
            if logger:
                logger.warning(
                    (
                        f"API: Delete repository {repository_name} failed - "
                        f"invalid Discord webhook URL"
                    )
                )
            return jsonify({"error": ERROR_INVALID_DISCORD_WEBHOOK}), 403

        # Delete from database
        try:
            db.execute("DELETE FROM repositories WHERE repo_id = ?", (repo_config["repo_id"],))

            # Note: We don't decrement total_repositories here because it tracks
            # cumulative additions. The statistic represents "total repositories ever
            # added", not current count

            if logger:
                logger.info(
                    "API: Repository %s (ID: %s) deleted successfully",
                    repository_name,
                    repo_config["repo_id"],
                )
            return jsonify({"message": "Repository deleted successfully"}), 200
        except sqlite3.Error as e:
            if logger:
                logger.error("API: Database error deleting repository %s: %s", repository_name, e)
            return jsonify({"error": ERROR_DATABASE}), 500


@api_bp.route("/repositories/verify", methods=["POST"])
@require_api_key_or_csrf
def api_verify_repository():  # pylint: disable=too-many-return-statements # NOSONAR
    """
    Verifies repository credentials for editing/deleting.
    Only requires repo_url and discord_webhook_url (no secret needed).

    Expected JSON payload:
    {
        "repo_url": "https://github.com/owner/repo",
        "discord_webhook_url": "https://discord.com/api/webhooks/..."
    }
    """
    # Check permission
    perm_check = check_permission("repositories-verify")
    if perm_check:
        return perm_check

    # Ensure dependencies are initialized
    assert github_handler is not None
    assert get_repository_by_id is not None

    if logger:
        logger.info(f"API: Verify repository request from {request.remote_addr}")
    data = request.get_json(silent=True)
    if not data:
        if logger:
            logger.warning("API: Verify repository rejected - missing JSON payload")
        return jsonify({"error": ERROR_MISSING_JSON}), 400

    repo_url = data.get("repo_url", "").strip()
    discord_webhook_url = data.get("discord_webhook_url", "").strip()

    if not all([repo_url, discord_webhook_url]):
        if logger:
            logger.warning("API: Verify repository rejected - missing required fields")
        return jsonify({"error": ERROR_MISSING_FIELDS}), 400

    # Extract owner and repo from URL
    repo_info = github_handler.extract_repo_info_from_url(repo_url)
    if not repo_info:
        if logger:
            logger.warning(f"API: Verify repository rejected - invalid URL: {repo_url}")
        return jsonify({"error": "Invalid GitHub repository URL"}), 400

    owner, repo_name = repo_info

    # Fetch repository data from GitHub
    github_data = github_handler.fetch_repo_data(owner, repo_name)
    if not github_data:
        if logger:
            logger.error(
                "API: Verify repository failed - could not fetch GitHub data for %s/%s",
                owner,
                repo_name,
            )
        return jsonify({"error": "Could not fetch repository data from GitHub"}), 400

    # Get repository from database
    repo_config = get_repository_by_id(github_data["repo_id"])
    if not repo_config:
        if logger:
            logger.warning(
                "API: Verify repository failed - repository not found: %s (ID: %s)",
                github_data["repo_full_name"],
                github_data["repo_id"],
            )
        return jsonify({"error": "Repository not found in database"}), 404

    # Verify webhook URL matches
    if repo_config["discord_webhook_url"] != discord_webhook_url:
        if logger:
            logger.warning(
                "API: Verify repository failed - invalid webhook URL for %s",
                github_data["repo_full_name"],
            )
        return jsonify({"error": ERROR_INVALID_DISCORD_WEBHOOK}), 403

    if logger:
        logger.info(
            "API: Repository verified successfully: %s (ID: %s)",
            github_data["repo_full_name"],
            github_data["repo_id"],
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


@api_bp.route("/events", methods=["GET"])
@require_api_key_or_csrf
def api_list_events():
    """
    Lists all available event types that can be enabled for repositories.

    Returns:
        JSON object with available event types:
        {
            "events": [
                {
                    "name": "star",
                    "description": "Triggered when a user stars the repository"
                },
                {
                    "name": "watch",
                    "description": "Triggered when a user watches the repository"
                }
            ],
            "total_events": 2,
            "description": "Use comma-separated event names when adding or updating repositories"
        }
    """
    # Check permission
    perm_check = check_permission("events-list")
    if perm_check:
        return perm_check

    events_info = [
        {
            "name": "star",
            "description": "Triggered when a user stars the repository",
            "github_event": "star",
        },
        {
            "name": "watch",
            "description": "Triggered when a user watches the repository",
            "github_event": "watch",
        },
    ]

    return (
        jsonify(
            {
                "events": events_info,
                "total_events": len(events_info),
                "description": (
                    "Use comma-separated event names when adding or updating repositories. "
                    "Example: 'star,watch'"
                ),
            }
        ),
        200,
    )


@api_bp.route("/permissions", methods=["GET"])
@require_api_key_or_csrf
def api_list_permissions():
    """
    Lists all available API permissions with their bit positions.

    Returns:
        JSON object with permission details, for example:

        {
            "permissions": [
                {"name": "generate-secret", "bit": 0, "value": 1},
                {"name": "repositories-add", "bit": 1, "value": 2},
            ],
            "max_value": 1023,
            "description": "Combine permission values using bitwise OR",
        }
    """
    # Check permission
    perm_check = check_permission("permissions-list")
    if perm_check:
        return perm_check

    if not bitmap_handler:
        return jsonify({"error": ERROR_PERMISSION_NOT_INITIALIZED}), 500

    # Use centralized permission configuration
    permissions_list = config.PERMISSIONS

    return (
        jsonify(
            {
                "permissions": permissions_list,
                "max_value": config.MAX_PERMISSION_VALUE,
                "total_permissions": len(permissions_list),
                "description": (
                    "Combine permission values using bitwise OR; example: "
                    "generate-secret (1) + repositories-add (2) = 3"
                ),
            }
        ),
        200,
    )


@api_bp.route("/permissions/calculate", methods=["POST"])
@require_api_key_or_csrf
def api_calculate_permissions():
    """
    Calculates the permission bitmap value from a list of permission names.

    Expected JSON payload:
    {
        "permissions": ["generate-secret", "repositories-add"]
    }

    Returns:
        JSON object with calculated bitmap:
        {
            "bitmap": 3,
            "permissions": ["generate-secret", "repositories-add"],
            "binary": "0b11",
            "breakdown": [
                {"name": "generate-secret", "bit": 0, "value": 1},
                {"name": "repositories-add", "bit": 1, "value": 2}
            ]
        }
    """
    # Check permission
    perm_check = check_permission("permissions-calculate")
    if perm_check:
        return perm_check

    if not bitmap_handler:
        return jsonify({"error": ERROR_PERMISSION_NOT_INITIALIZED}), 500

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": ERROR_MISSING_JSON}), 400

    permission_names = data.get("permissions", [])
    if not isinstance(permission_names, list):
        return jsonify({"error": "permissions must be an array of permission names"}), 400

    if not permission_names:
        return jsonify({"error": "At least one permission must be provided"}), 400

    # Validate all permission names
    invalid_permissions = [p for p in permission_names if p not in bitmap_handler.key_list]
    if invalid_permissions:
        return (
            jsonify(
                {
                    "error": f"Invalid permission names: {', '.join(invalid_permissions)}",
                    "valid_permissions": bitmap_handler.key_list,
                }
            ),
            400,
        )

    # Calculate bitmap
    bitmap = 0
    breakdown = []
    for permission_name in permission_names:
        bit_position = bitmap_handler.key_list.index(permission_name)
        bit_value = 1 << bit_position
        bitmap |= bit_value
        breakdown.append({"name": permission_name, "bit": bit_position, "value": bit_value})

    return (
        jsonify(
            {
                "bitmap": bitmap,
                "permissions": permission_names,
                "binary": bin(bitmap),
                "hexadecimal": hex(bitmap),
                "breakdown": breakdown,
                "description": (
                    f"Use this bitmap value ({bitmap}) when creating or updating API keys"
                ),
            }
        ),
        200,
    )


@api_bp.route("/permissions/decode", methods=["POST"])
@require_api_key_or_csrf
def api_decode_permissions():
    """
    Decodes a permission bitmap value to show which permissions are enabled.
    Accepts decimal, binary (0b prefix), or hexadecimal (0x prefix) values.

    Expected JSON payload:
    {
        "bitmap": 3  // or "0b11" or "0x3"
    }

    Returns:
        JSON object with decoded permissions:
        {
            "bitmap": 3,
            "binary": "0b11",
            "hexadecimal": "0x3",
            "permissions": ["generate-secret", "repositories-add"],
            "breakdown": [
                {"name": "generate-secret", "bit": 0, "value": 1},
                {"name": "repositories-add", "bit": 1, "value": 2}
            ]
        }
    """
    # Check permission
    perm_check = check_permission("permissions-decode")
    if perm_check:
        return perm_check

    if not bitmap_handler:
        return jsonify({"error": "Permission system not initialized"}), 500

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": ERROR_MISSING_JSON}), 400

    bitmap_value = data.get("bitmap")
    if bitmap_value is None:
        return jsonify({"error": "bitmap value is required"}), 400

    # Convert string representations to integer
    try:
        if isinstance(bitmap_value, str):
            # Handle binary (0b), hexadecimal (0x), or decimal string
            bitmap_int = int(bitmap_value, 0)  # Auto-detects base from prefix
        elif isinstance(bitmap_value, int):
            bitmap_int = bitmap_value
        else:
            return (
                jsonify(
                    {
                        "error": (
                            "bitmap must be an integer, binary string (0b...), "
                            "or hexadecimal string (0x...)"
                        )
                    }
                ),
                400,
            )
    except ValueError:
        return (
            jsonify(
                {
                    "error": (
                        "Invalid bitmap format. Use decimal (3), binary (0b11), "
                        "or hexadecimal (0x3)"
                    )
                }
            ),
            400,
        )

    # Validate bitmap range
    max_bitmap = (1 << len(bitmap_handler.key_list)) - 1
    if bitmap_int < 0:
        return jsonify({"error": "bitmap cannot be negative"}), 400
    if bitmap_int > max_bitmap:
        return (
            jsonify(
                {
                    "error": f"bitmap value {bitmap_int} exceeds maximum {max_bitmap}",
                    "max_value": max_bitmap,
                }
            ),
            400,
        )

    # Special case: bitmap 0 means no permissions
    if bitmap_int == 0:
        return (
            jsonify(
                {
                    "bitmap": 0,
                    "binary": "0b0",
                    "hexadecimal": "0x0",
                    "permissions": [],
                    "breakdown": [],
                    "description": "No permissions enabled",
                }
            ),
            200,
        )

    # Decode bitmap to permissions
    permissions = []
    breakdown = []

    for bit_position, permission_name in enumerate(bitmap_handler.key_list):
        bit_value = 1 << bit_position
        if bitmap_int & bit_value:
            permissions.append(permission_name)
            breakdown.append({"name": permission_name, "bit": bit_position, "value": bit_value})

    return (
        jsonify(
            {
                "bitmap": bitmap_int,
                "binary": bin(bitmap_int),
                "hexadecimal": hex(bitmap_int),
                "permissions": permissions,
                "breakdown": breakdown,
                "description": f"Bitmap {bitmap_int} enables {len(permissions)} permission(s)",
            }
        ),
        200,
    )


def require_api_key_or_csrf_or_admin(f):
    """
    Custom decorator for /api/stats that accepts:
    - API key in Authorization header, OR
    - CSRF token in X-CSRF-Token header, OR
    - Admin session cookie
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for admin session first
        if session.get("admin_authenticated"):
            # Validate session is still valid (same logic as require_admin_auth)
            admin_login_time = session.get("admin_login_time", 0)
            current_time = int(time.time())
            session_age = current_time - admin_login_time

            if session_age <= 300:  # 5 minute timeout
                if logger:
                    logger.debug("API route access granted: valid admin session")
                # Refresh session timestamp (sliding session)
                session["admin_login_time"] = current_time
                session.modified = True
                return f(*args, **kwargs)

        # Fall back to standard API key or CSRF check
        assert _require_api_key_or_csrf is not None
        return _require_api_key_or_csrf(f)(*args, **kwargs)

    return decorated_function


@api_bp.route("/stats", methods=["GET"])
@require_api_key_or_csrf_or_admin
def api_get_stats():
    """
    Get system statistics (requires API key, CSRF token, or admin session).

    Returns comprehensive statistics including:
    - Total counts (repositories, API keys, events, etc.)
    - Deletion statistics by reason
    - Top users by valid and invalid events
    """
    # Check permission (CSRF tokens and admin sessions bypass this)
    perm_check = check_permission("stats")
    if perm_check:
        return perm_check

    # Ensure dependencies are initialized
    assert get_db is not None
    assert get_all_stats is not None
    assert get_top_users is not None

    if logger:
        logger.debug(f"Stats request from {request.remote_addr}")

    if not get_all_stats or not get_top_users:
        return jsonify({"error": "Statistics functions not available"}), 500

    try:
        # Get all statistics
        all_stats = get_all_stats()

        # Get top users
        top_users_valid = get_top_users("valid", 10)
        top_users_invalid = get_top_users("invalid", 10)

        # Count current repositories and API keys
        db = get_db()
        current_repos = db.execute("SELECT COUNT(*) as count FROM repositories").fetchone()["count"]
        current_api_keys = db.execute("SELECT COUNT(*) as count FROM api_keys").fetchone()["count"]
        
        # Count active API keys and admin keys
        active_api_keys = db.execute("SELECT COUNT(*) as count FROM api_keys WHERE is_active = 1").fetchone()["count"]
        admin_api_keys = db.execute("SELECT COUNT(*) as count FROM api_keys WHERE is_admin_key = 1").fetchone()["count"]

        # Organize stats into categories
        response = {
            "totals": {
                "repositories_current": current_repos,
                "api_keys_current": current_api_keys,
                "api_keys_active": active_api_keys,
                "api_keys_admin": admin_api_keys,
                "repositories_ever_added": all_stats.get("total_repositories", 0),
                "api_keys_ever_created": all_stats.get("total_api_keys", 0),
                "discord_messages_sent": all_stats.get("total_discord_messages", 0),
                "events_received": all_stats.get("total_events_received", 0),
                "unique_events": all_stats.get("total_unique_events", 0),
                "duplicate_events": all_stats.get("total_duplicate_events", 0),
            },
            "deletions": {
                "repos_inactive_360_days": all_stats.get("total_repositories_deleted_inactive", 0),
                "repos_github_deleted": all_stats.get("total_repositories_deleted_repo_gone", 0),
                "repos_webhook_invalid": all_stats.get(
                    "total_repositories_deleted_webhook_gone", 0
                ),
                "api_keys_inactive_360_days": all_stats.get("total_api_keys_deleted_inactive", 0),
            },
            "top_users": {
                "valid_events": top_users_valid,
                "invalid_events": top_users_invalid,
            },
            "cleanup_config": {
                "repositories_inactive_days": config.CLEANUP_INACTIVE_REPOSITORIES_DAYS,
                "webhooks_inactive_days": config.CLEANUP_INACTIVE_WEBHOOKS_DAYS,
                "api_keys_inactive_days": config.CLEANUP_INACTIVE_API_KEYS_DAYS,
            },
            "timestamp": int(time.time()),
        }

        if logger:
            logger.info("Stats retrieved successfully")
        return jsonify(response), 200

    except Exception as e:
        if logger:
            logger.error(f"Error retrieving stats: {e}")
        return jsonify({"error": ERROR_DATABASE}), 500
