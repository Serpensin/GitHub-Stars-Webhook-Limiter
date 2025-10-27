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
from functools import wraps

from flask import Blueprint, jsonify, request

api_bp = Blueprint("api", __name__, url_prefix="/api")

# Error message constants
ERROR_DATABASE = "Database error occurred"
ERROR_MISSING_JSON = "Missing JSON payload"
ERROR_MISSING_FIELDS = "Missing required fields"
ERROR_INVALID_SECRET = "Invalid secret"
ERROR_INVALID_DISCORD_WEBHOOK = "Invalid Discord webhook URL"
ERROR_PERMISSION_NOT_INITIALIZED = "Permission system not initialized"

# These will be set by main.py when registering blueprints
logger = None
_require_api_key_or_csrf = None  # Store the actual decorator
extract_repo_info_from_url = None
fetch_repo_data_from_github = None
verify_discord_webhook = None
encrypt_secret = None
get_db = None
get_repository_by_id = None
verify_secret = None
bitmap_handler = None  # Add bitmap_handler for permission calculations


def require_api_key_or_csrf(f):
    """Wrapper decorator that delegates to the actual decorator after initialization"""

    @wraps(f)
    def wrapper(*args, **kwargs):
        return _require_api_key_or_csrf(f)(*args, **kwargs)

    return wrapper


def init_api_routes(
    _logger,
    _require_api_key_or_csrf_func,
    _extract_repo_info_from_url,
    _fetch_repo_data_from_github,
    _verify_discord_webhook,
    _encrypt_secret,
    _get_db,
    _get_repository_by_id,
    _verify_secret,
    _bitmap_handler,
):
    """Initialize route dependencies"""
    global logger, _require_api_key_or_csrf, extract_repo_info_from_url
    global fetch_repo_data_from_github, verify_discord_webhook, encrypt_secret
    global get_db, get_repository_by_id, verify_secret, bitmap_handler

    logger = _logger
    _require_api_key_or_csrf = _require_api_key_or_csrf_func
    extract_repo_info_from_url = _extract_repo_info_from_url
    fetch_repo_data_from_github = _fetch_repo_data_from_github
    verify_discord_webhook = _verify_discord_webhook
    encrypt_secret = _encrypt_secret
    get_db = _get_db
    get_repository_by_id = _get_repository_by_id
    verify_secret = _verify_secret
    bitmap_handler = _bitmap_handler


@api_bp.route("/generate-secret", methods=["GET"])
@require_api_key_or_csrf
def api_generate_secret():
    """
    Generates a cryptographically secure random secret.
    """
    logger.debug(f"Secret generation requested from {request.remote_addr}")
    secret = secrets.token_urlsafe(32)
    return jsonify({"secret": secret}), 200


@api_bp.route("/repositories", methods=["POST", "PATCH", "DELETE"])
@require_api_key_or_csrf
def api_manage_repository():  # pylint: disable=too-many-return-statements
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
    if request.method == "POST":
        logger.info(f"API: Add repository request from {request.remote_addr}")
        data = request.get_json(silent=True)
        if not data:
            logger.warning("API: Add repository rejected - missing JSON payload")
            return jsonify({"error": ERROR_MISSING_JSON}), 400

        repo_url = data.get("repo_url", "").strip()
        secret = data.get("secret", "").strip()
        discord_webhook_url = data.get("discord_webhook_url", "").strip()
        enabled_events = data.get("enabled_events", "").strip()

        # Validate inputs
        if not all([repo_url, secret, discord_webhook_url, enabled_events]):
            logger.warning("API: Add repository rejected - missing required fields")
            return jsonify({"error": ERROR_MISSING_FIELDS}), 400

        # Validate enabled events
        events = enabled_events.split(",")
        valid_events = {"star", "watch"}
        if not all(event in valid_events for event in events):
            logger.warning(f"API: Add repository rejected - invalid event types: {enabled_events}")
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
                    {"error": "Could not fetch repository data from GitHub. Please check the URL."}
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
            logger.warning(
                "API: Repository already exists: %s (ID: %s)",
                github_data["repo_full_name"],
                github_data["repo_id"],
            )
            return jsonify({"error": "Repository already exists in the database"}), 409
        except sqlite3.Error as e:
            logger.error(
                "API: Database error adding repository %s: %s", github_data["repo_full_name"], e
            )
            return jsonify({"error": ERROR_DATABASE}), 500

    elif request.method == "PATCH":
        logger.info(f"API: Update repository request from {request.remote_addr}")
        data = request.get_json(silent=True)
        if not data:
            logger.warning("API: Update repository rejected - missing JSON payload")
            return jsonify({"error": ERROR_MISSING_JSON}), 400

        repository_name = data.get("repository_name", "").strip()
        discord_webhook_url = data.get("discord_webhook_url", "").strip()

        if not repository_name or not discord_webhook_url:
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
            logger.warning(
                f"API: Update repository failed - repository not found: {repository_name}"
            )
            return jsonify({"error": "Repository not found"}), 404

        # Verify Discord webhook URL for authentication
        if repo_config["discord_webhook_url"] != discord_webhook_url:
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
            if not verify_discord_webhook(new_discord_webhook_url):
                logger.warning(
                    f"API: Update repository {repository_name} failed - invalid new Discord webhook"
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
                logger.warning(
                    f"API: Update repository rejected - invalid event types: {enabled_events}"
                )
                return jsonify({"error": "Invalid event types"}), 400
            updates.append("enabled_events = ?")
            params.append(enabled_events)
            changes.append("events")

        # Check if any updates were requested
        if not updates:
            logger.warning(
                f"API: Update repository {repository_name} rejected - no updates provided"
            )
            return jsonify({"error": "No updates provided"}), 400

        updates.append("updated_at = CURRENT_TIMESTAMP")

        params.append(repo_config["repo_id"])

        # Update database
        try:
            db.execute(f"UPDATE repositories SET {', '.join(updates)} WHERE repo_id = ?", params)
            logger.info(
                "API: Repository %s (ID: %s) updated successfully - Changed: %s",
                repository_name,
                repo_config["repo_id"],
                ", ".join(changes),
            )
            return jsonify({"message": "Repository updated successfully"}), 200
        except sqlite3.Error as e:
            logger.error("API: Database error updating repository %s: %s", repository_name, e)
            return jsonify({"error": ERROR_DATABASE}), 500

    else:  # DELETE
        logger.info(f"API: Delete repository request from {request.remote_addr}")
        data = request.get_json(silent=True)
        if not data:
            logger.warning("API: Delete repository rejected - missing JSON payload")
            return jsonify({"error": ERROR_MISSING_JSON}), 400

        repository_name = data.get("repository_name", "").strip()
        discord_webhook_url = data.get("discord_webhook_url", "").strip()

        if not repository_name or not discord_webhook_url:
            logger.warning("API: Delete repository rejected - missing required fields")
            return jsonify({"error": ERROR_MISSING_FIELDS}), 400

        # Get repository from database by name
        db = get_db()
        repo_config = db.execute(
            "SELECT * FROM repositories WHERE repo_full_name = ?", (repository_name,)
        ).fetchone()

        if not repo_config:
            logger.warning(
                f"API: Delete repository failed - repository not found: {repository_name}"
            )
            return jsonify({"error": "Repository not found"}), 404

        # Verify Discord webhook URL matches
        if repo_config["discord_webhook_url"] != discord_webhook_url:
            logger.warning(
                f"API: Delete repository {repository_name} failed - invalid Discord webhook URL"
            )
            return jsonify({"error": ERROR_INVALID_DISCORD_WEBHOOK}), 403

        # Delete from database
        try:
            db.execute("DELETE FROM repositories WHERE repo_id = ?", (repo_config["repo_id"],))
            logger.info(
                "API: Repository %s (ID: %s) deleted successfully",
                repository_name,
                repo_config["repo_id"],
            )
            return jsonify({"message": "Repository deleted successfully"}), 200
        except sqlite3.Error as e:
            logger.error("API: Database error deleting repository %s: %s", repository_name, e)
            return jsonify({"error": ERROR_DATABASE}), 500


@api_bp.route("/repositories/verify", methods=["POST"])
@require_api_key_or_csrf
def api_verify_repository():  # pylint: disable=too-many-return-statements
    """
    Verifies repository credentials for editing/deleting.
    Only requires repo_url and discord_webhook_url (no secret needed).

    Expected JSON payload:
    {
        "repo_url": "https://github.com/owner/repo",
        "discord_webhook_url": "https://discord.com/api/webhooks/..."
    }
    """
    logger.info(f"API: Verify repository request from {request.remote_addr}")
    data = request.get_json(silent=True)
    if not data:
        logger.warning("API: Verify repository rejected - missing JSON payload")
        return jsonify({"error": ERROR_MISSING_JSON}), 400

    repo_url = data.get("repo_url", "").strip()
    discord_webhook_url = data.get("discord_webhook_url", "").strip()

    if not all([repo_url, discord_webhook_url]):
        logger.warning("API: Verify repository rejected - missing required fields")
        return jsonify({"error": ERROR_MISSING_FIELDS}), 400

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
            repo_name,
        )
        return jsonify({"error": "Could not fetch repository data from GitHub"}), 400

    # Get repository from database
    repo_config = get_repository_by_id(github_data["repo_id"])
    if not repo_config:
        logger.warning(
            "API: Verify repository failed - repository not found: %s (ID: %s)",
            github_data["repo_full_name"],
            github_data["repo_id"],
        )
        return jsonify({"error": "Repository not found in database"}), 404

    # Verify webhook URL matches
    if repo_config["discord_webhook_url"] != discord_webhook_url:
        logger.warning(
            "API: Verify repository failed - invalid webhook URL for %s",
            github_data["repo_full_name"],
        )
        return jsonify({"error": ERROR_INVALID_DISCORD_WEBHOOK}), 403

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
        JSON object with permission details:
        {
            "permissions": [
                {"name": "generate-secret", "bit": 0, "value": 1},
                {"name": "repositories-add", "bit": 1, "value": 2},
                ...
            ],
            "max_value": 31,
            "description": "Combine permission values using bitwise OR to create permission bitmap"
        }
    """
    if not bitmap_handler:
        return jsonify({"error": ERROR_PERMISSION_NOT_INITIALIZED}), 500

    permissions_list = []
    for bit_position, permission_name in enumerate(bitmap_handler.key_list):
        permissions_list.append(
            {
                "name": permission_name,
                "bit": bit_position,
                "value": 1 << bit_position,
                "description": f"Allows access to /{permission_name.replace('-', '/')} endpoint",
            }
        )

    return (
        jsonify(
            {
                "permissions": permissions_list,
                "max_value": (1 << len(bitmap_handler.key_list)) - 1,
                "total_permissions": len(bitmap_handler.key_list),
                "description": (
                    "Combine permission values using bitwise OR (or addition) to create "
                    "permission bitmap. Example: generate-secret (1) + repositories-add (2) = 3"
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
