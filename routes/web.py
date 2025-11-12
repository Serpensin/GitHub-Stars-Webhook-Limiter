"""
Web Routes

Public-facing routes:
- /: Main web interface
- /docs: API documentation (Redoc)
- /try: Interactive API testing (Swagger UI)
- /spec: OpenAPI specification (JSON/YAML)
- /license: MIT License file
- /stats: Public statistics page (JSON)
- /webhook: GitHub webhook handler
"""

import os
import secrets
import sys
import time
from typing import Any, Callable, Literal, Optional

# Add .config folder to path before importing config and modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".config"))

import config  # type: ignore
from flask import (  # noqa: E402
    Blueprint,
    jsonify,
    render_template,
    request,
    send_file,
    session,
)

from modules.DatabaseWrapper import DatabaseWrapper  # noqa: E402

web_bp = Blueprint("web", __name__)

# These will be set by main.py when registering blueprints
logger: Optional[Any] = None
db_wrapper: Optional[DatabaseWrapper] = None
get_db: Optional[Callable[[], Any]] = None
get_repository_by_id: Optional[Callable[[int], Optional[dict[str, Any]]]] = None
decrypt_secret: Optional[Callable[[bytes], str]] = None
verify_github_signature: Optional[Callable[[str, str, bytes], bool]] = None
has_user_triggered_event_before: Optional[Callable[[int, int, str], bool]] = None
discord_handler: Optional[Any] = None
add_user_event: Optional[Callable[[int, int, str], None]] = None
increment_stat: Optional[Callable[[str], None]] = None  # amount parameter has default value
get_all_stats: Optional[Callable[[], dict]] = None
get_top_users: Optional[Callable[[str, int], list[dict]]] = None


def init_web_routes(
    _logger,
    _db_type: Literal["sqlite", "postgresql"],
    _get_repository_by_id,
    _decrypt_secret,
    _verify_github_signature,
    _has_user_triggered_event_before,
    _discord_handler,
    _add_user_event,
    _get_db=None,
    _increment_stat=None,
    _get_all_stats=None,
    _get_top_users=None,
):
    """Initialize route dependencies"""
    global logger, db_wrapper, get_db, get_repository_by_id, decrypt_secret, verify_github_signature
    global has_user_triggered_event_before, discord_handler, add_user_event
    global increment_stat, get_all_stats, get_top_users

    logger = _logger
    db_wrapper = DatabaseWrapper(_db_type)
    get_db = _get_db
    get_repository_by_id = _get_repository_by_id
    decrypt_secret = _decrypt_secret
    verify_github_signature = _verify_github_signature
    has_user_triggered_event_before = _has_user_triggered_event_before
    discord_handler = _discord_handler
    add_user_event = _add_user_event
    increment_stat = _increment_stat
    get_all_stats = _get_all_stats
    get_top_users = _get_top_users

    if logger:
        logger.debug("Web routes initialized")


@web_bp.route("/", methods=["GET"])
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
            session["used_nonces"] = []
            if logger:
                logger.debug("Generated new CSRF token for session")

        # Always update timestamp on page load to reset the 5-minute expiry window
        # Use actual current timestamp (seconds since epoch)
        session["csrf_token_timestamp"] = int(time.time())

        if logger:
            logger.debug(f"Web interface accessed from {request.remote_addr}")
        return render_template("index.html", csrf_token=session["csrf_token"])
    except Exception as e:  # pylint: disable=broad-exception-caught
        if logger:
            logger.error(f"Error serving frontend: {e}")
        return jsonify(
            {
                "app": config.APP_NAME,
                "version": config.APP_VERSION,
                "status": "running",
                "message": "Frontend not available. Use API endpoints.",
            }
        )


@web_bp.route("/health")
def health():
    """
    Health check endpoint for monitoring and container orchestration.
    Returns JSON with application status and database connectivity.
    Designed to be called with User-Agent: Healthcheck for filtered logging.

    Returns:
        - 200 OK if both app and database are healthy
        - 503 Service Unavailable if database is unreachable
    """
    # Determine log level based on User-Agent
    user_agent = request.headers.get("User-Agent", "")
    is_healthcheck_agent = user_agent == "Healthcheck"

    if logger:
        if is_healthcheck_agent:
            logger.debug(f"Health check from {request.remote_addr}")
        else:
            logger.info(f"Health check from {request.remote_addr} (User-Agent: {user_agent})")

    # Check database connectivity
    db_status = "unknown"
    db_type = "unknown"
    db_error = None

    try:
        if get_db and db_wrapper:
            db = get_db()
            db_type = db_wrapper.db_type

            # Try a simple query to verify database is accessible
            cursor = db.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()

            db_status = "healthy"
            if logger and not is_healthcheck_agent:
                logger.debug(f"Database health check passed ({db_type})")

    except Exception as e:
        db_status = "unhealthy"
        db_error = str(e)
        if logger:
            logger.error(f"Database health check failed: {e}")

    # Determine overall status
    overall_status = "healthy" if db_status == "healthy" else "unhealthy"
    http_status = 200 if db_status == "healthy" else 503

    response_data = {
        "status": overall_status,
        "app": config.APP_NAME,
        "version": config.APP_VERSION,
        "database": {
            "type": db_type,
            "status": db_status,
        },
    }

    # Include error details only if database is unhealthy
    if db_error:
        response_data["database"]["error"] = db_error

    # Create response with cache control headers
    response = jsonify(response_data)
    response.status_code = http_status

    # Set cache control headers to allow caching for max 10 seconds
    # This prevents excessive database checks while ensuring timely health updates
    response.headers["Cache-Control"] = "public, max-age=10, must-revalidate"

    return response


@web_bp.route("/docs")
def docs():
    """API documentation page (Redoc UI)"""
    return render_template("docs.html")


@web_bp.route("/stats")
def stats_page():
    """
    Public statistics page showing system statistics.
    Generates CSRF token for API access.
    """
    try:
        # Generate CSRF token if not already in session
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
            session["used_nonces"] = []
            if logger:
                logger.debug("Generated new CSRF token for stats page session")

        # Update timestamp on page load
        session["csrf_token_timestamp"] = int(time.time())

        if logger:
            logger.debug(f"Stats page accessed from {request.remote_addr}")
        return render_template("stats.html", csrf_token=session["csrf_token"])
    except Exception as e:  # pylint: disable=broad-exception-caught
        if logger:
            logger.error(f"Error serving stats page: {e}")
        return "Internal Server Error", 500


@web_bp.route("/try")
def try_api():
    """
    Interactive API testing page (Swagger UI).
    Allows testing API endpoints with authentication.
    """
    return render_template("swagger.html")


@web_bp.route("/spec")
def spec():
    """
    Serves the OpenAPI specification file as plain text in browser.
    Returns the YAML file for agents and other consumers.
    """
    spec_path = os.path.join(os.path.dirname(__file__), "..", "static", "openapi.yaml")
    return send_file(
        spec_path,
        mimetype="text/plain; charset=utf-8",
        as_attachment=False,
        download_name="openapi.yaml",
    )


@web_bp.route("/license")
def license_file():
    """
    Serves the LICENSE.txt file with HTML formatting.
    """
    license_path = os.path.join(os.path.dirname(__file__), "..", "LICENSE.txt")

    # Read the license file
    try:
        with open(license_path, "r", encoding="utf-8") as f:
            license_text = f.read()
    except Exception as e:
        if logger:
            logger.error(f"Failed to read LICENSE.txt: {e}")
        return "License file not found", 404

    return render_template("license.html", license_text=license_text)


@web_bp.route("/webhook", methods=["POST"])
def handle_webhook():  # pylint: disable=too-many-return-statements,too-many-branches # NOSONAR
    """
    Handles incoming GitHub webhook events (star, watch, ping).

    This endpoint:
    - Handles GitHub's ping event for webhook verification
    - Validates webhook signatures
    - Processes star and watch events
    - Sends Discord notifications for first-time events
    """
    # Ensure dependencies are initialized
    assert get_repository_by_id is not None
    assert decrypt_secret is not None
    assert verify_github_signature is not None
    assert has_user_triggered_event_before is not None
    assert discord_handler is not None
    assert add_user_event is not None
    assert get_db is not None

    # Handle ping event from GitHub webhook setup
    event_type = request.headers.get("x-github-event")
    if logger:
        logger.info(f"Received webhook event: {event_type} from {request.remote_addr}")

    if event_type == "ping":
        if logger:
            logger.info("Webhook ping event received and acknowledged")
        return jsonify({"message": "Webhook received and verified"}), 200

    # Validate JSON payload
    if not request.is_json:
        if logger:
            logger.warning("Webhook rejected: not JSON")
        return jsonify({"error": "Expected application/json"}), 400

    data = request.get_json(silent=True)
    if not data:
        if logger:
            logger.warning("Webhook rejected: malformed or empty JSON")
        return jsonify({"error": "Malformed or empty JSON"}), 400

    # Extract repository information
    repo_id = data.get("repository", {}).get("id")
    if not repo_id:
        if logger:
            logger.warning("Webhook rejected: missing repository.id")
        return jsonify({"error": "Missing repository.id"}), 400

    # Get repository configuration
    repo_config = get_repository_by_id(repo_id)
    if not repo_config:
        if logger:
            logger.warning(f"Webhook rejected: repository {repo_id} not configured")
        return jsonify({"error": "Repository not configured"}), 404

    # Validate webhook signature
    signature_header = request.headers.get("x-hub-signature-256")
    if not signature_header:
        if logger:
            logger.warning(f"Webhook rejected for repo {repo_id}: missing signature")
        return jsonify({"error": "Missing signature"}), 403

    # Decrypt secret and validate signature
    try:
        secret = decrypt_secret(repo_config["secret_encrypted"])
        if not verify_github_signature(secret, signature_header, request.data):
            if logger:
                logger.warning(f"Webhook rejected for repo {repo_id}: invalid signature")
            return jsonify({"error": "Invalid signature"}), 403
    except Exception as e:  # pylint: disable=broad-exception-caught
        if logger:
            logger.error(f"Error validating signature for repo {repo_id}: {e}")
        return jsonify({"error": "Signature validation failed"}), 403

    # Update last_event_received timestamp for this repository
    try:
        db = get_db()
        db.execute(
            "UPDATE repositories SET last_event_received = ? WHERE repo_id = ?",
            (int(time.time()), repo_id),
        )
        if logger:
            logger.debug(f"Updated last_event_received for repo {repo_id}")
    except Exception as e:  # pylint: disable=broad-exception-caught
        if logger:
            logger.error(f"Failed to update last_event_received for repo {repo_id}: {e}")

    # Increment total events received statistic
    if increment_stat:
        increment_stat("total_events_received")

    # Check if event type is supported
    if event_type not in ["star", "watch"]:
        if logger:
            logger.warning(f"Unsupported event type: {event_type} for repo {repo_id}")
        return jsonify({"error": "Unsupported event type"}), 422

    # Check if this event type is enabled for this repository
    enabled_events = repo_config["enabled_events"].split(",")
    if event_type not in enabled_events:
        if logger:
            logger.info(f"{event_type} event received but not enabled for repo {repo_id}")
        return (
            jsonify({"message": f"{event_type} events not enabled for this repository"}),
            200,
        )

    # Check action
    action = data.get("action")
    if action not in ("created", "started"):  # 'started' is for watch events
        if logger:
            logger.debug(f"Action '{action}' not processed for {event_type} on repo {repo_id}")
        return jsonify({"message": f"Action '{action}' not processed"}), 200

    # Get sender information
    sender_id = data.get("sender", {}).get("id")
    sender_login = data.get("sender", {}).get("login", "unknown")
    if sender_id is None:
        if logger:
            logger.warning(f"Webhook rejected for repo {repo_id}: missing sender ID")
        return jsonify({"error": "Missing sender ID"}), 400

    # Check if user has already triggered this event
    if not has_user_triggered_event_before(sender_id, repo_id, event_type):
        if logger:
            logger.info(
                "Processing first-time %s from %s (%s) on repo %s",
                event_type,
                sender_login,
                sender_id,
                repo_id,
            )

        # Update user statistics - valid event
        try:
            db = get_db()
            assert db_wrapper is not None
            query = db_wrapper.build_upsert_user_statistics_valid()
            db.execute(
                query,
                (
                    sender_id,
                    sender_login,
                    int(time.time()),
                ),
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            if logger:
                logger.error(f"Failed to update user statistics for user {sender_id}: {e}")

        if discord_handler.send_notification(
            webhook_url=repo_config["discord_webhook_url"],
            event_data=data,
            event_type=event_type,
        ):
            add_user_event(sender_id, repo_id, event_type)

            # Increment unique events counter
            if increment_stat:
                increment_stat("total_unique_events")
                increment_stat("total_discord_messages")

            if logger:
                logger.info(
                    "Successfully processed %s event from %s on repo %s",
                    event_type,
                    sender_login,
                    repo_id,
                )
            return jsonify({"message": "Event processed and notification sent"}), 200
        if logger:
            logger.error(
                "Failed to send Discord notification for %s from %s on repo %s",
                event_type,
                sender_login,
                repo_id,
            )
        return jsonify({"error": "Failed to send Discord notification"}), 500

    # Duplicate event - update user statistics as invalid
    try:
        db = get_db()
        assert db_wrapper is not None
        query = db_wrapper.build_upsert_user_statistics_invalid()
        db.execute(
            query,
            (
                sender_id,
                sender_login,
                int(time.time()),
            ),
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
        if logger:
            logger.error(f"Failed to update user statistics for user {sender_id}: {e}")

    # Increment duplicate events counter
    if increment_stat:
        increment_stat("total_duplicate_events")

    if logger:
        logger.debug(
            "Duplicate %s event from %s (%s) on repo %s - ignored",
            event_type,
            sender_login,
            sender_id,
            repo_id,
        )
    return jsonify({"message": "Event already processed for this user"}), 200
