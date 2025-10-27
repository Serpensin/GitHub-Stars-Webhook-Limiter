"""
Web Routes

Public-facing routes:
- /: Main web interface
- /docs: API documentation (Redoc)
- /try: Interactive API testing (Swagger UI)
- /spec: OpenAPI specification (JSON/YAML)
- /license: MIT License file
- /webhook: GitHub webhook handler
"""

import secrets

from flask import Blueprint, jsonify, render_template, request, send_file, session

web_bp = Blueprint("web", __name__)

# These will be set by main.py when registering blueprints
logger = None
get_repository_by_id = None
decrypt_secret = None
verify_github_signature = None
has_user_triggered_event_before = None
send_discord_notification = None
add_user_event = None


def init_web_routes(
    _logger,
    _get_repository_by_id,
    _decrypt_secret,
    _verify_github_signature,
    _has_user_triggered_event_before,
    _send_discord_notification,
    _add_user_event,
):
    """Initialize route dependencies"""
    global logger, get_repository_by_id, decrypt_secret, verify_github_signature
    global has_user_triggered_event_before, send_discord_notification, add_user_event

    logger = _logger
    get_repository_by_id = _get_repository_by_id
    decrypt_secret = _decrypt_secret
    verify_github_signature = _verify_github_signature
    has_user_triggered_event_before = _has_user_triggered_event_before
    send_discord_notification = _send_discord_notification
    add_user_event = _add_user_event


@web_bp.route("/", methods=["GET"])
def index():
    """
    Serves the frontend HTML page with CSRF token generation.
    Generates a unique CSRF token for this session to prevent CSRF attacks.
    Also initializes timestamp for token expiry validation.
    """
    import time

    import config  # type: ignore  # imported here to avoid import order issues

    try:
        # Generate CSRF token if not already in session
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
            session["used_nonces"] = []
            logger.debug("Generated new CSRF token for session")

        # Always update timestamp on page load to reset the 5-minute expiry window
        # Use actual current timestamp (seconds since epoch)
        session["csrf_token_timestamp"] = int(time.time())

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


@web_bp.route("/docs")
def docs():
    """API documentation page (Redoc UI)"""
    return render_template("docs.html")


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
    import os

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
    import os

    license_path = os.path.join(os.path.dirname(__file__), "..", "LICENSE.txt")

    # Read the license file
    try:
        with open(license_path, "r", encoding="utf-8") as f:
            license_text = f.read()
    except Exception as e:
        logger.error(f"Failed to read LICENSE.txt: {e}")
        return "License file not found", 404

    return render_template("license.html", license_text=license_text)


@web_bp.route("/webhook", methods=["POST"])
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
            jsonify({"message": f"{event_type} events not enabled for this repository"}),
            200,
        )

    # Check action
    action = data.get("action")
    if action not in ("created", "started"):  # 'started' is for watch events
        logger.debug(f"Action '{action}' not processed for {event_type} on repo {repo_id}")
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
            repo_id,
        )
        if send_discord_notification(repo_config["discord_webhook_url"], data, event_type):
            add_user_event(sender_id, repo_id, event_type)
            logger.info(
                "Successfully processed %s event from %s on repo %s",
                event_type,
                sender_login,
                repo_id,
            )
            return jsonify({"message": "Event processed and notification sent"}), 200
        logger.error(
            "Failed to send Discord notification for %s from %s on repo %s",
            event_type,
            sender_login,
            repo_id,
        )
        return jsonify({"error": "Failed to send Discord notification"}), 500

    logger.debug(
        "Duplicate %s event from %s (%s) on repo %s - ignored",
        event_type,
        sender_login,
        sender_id,
        repo_id,
    )
    return jsonify({"message": "Event already processed for this user"}), 200
