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
import secrets
import sqlite3
import sys

import requests
import sentry_sdk
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, g, jsonify, render_template, request

load_dotenv()
APP_NAME = "GitHub_Events_Limiter"
APP_VERSION = "2.0.0"

# Initialize encryption key (should be stored securely in production)
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    # Generate a key if not present and save it
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print("Generated new encryption key. Add this to your .env file:")
    print(f"ENCRYPTION_KEY={ENCRYPTION_KEY}")

cipher_suite = Fernet(
    ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY
)

# Initialize Sentry SDK for error monitoring and performance tracing
sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN"),
    send_default_pii=True,
    traces_sample_rate=1.0,
    profile_session_sample_rate=1.0,
    profile_lifecycle="trace",
    environment="Production",
    release=f"{APP_NAME}@{APP_VERSION}",
)

app = Flask(__name__)

os.makedirs(APP_NAME, exist_ok=True)

# Initialize database
try:
    conn = sqlite3.connect(os.path.join(APP_NAME, "data.db"))
    c = conn.cursor()

    # Table for tracking starred/watched repos
    c.execute(
        """
    CREATE TABLE IF NOT EXISTS user_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        github_user_id INTEGER NOT NULL,
        repository_id INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        UNIQUE(github_user_id, repository_id, event_type)
    )
    """
    )

    # Table for repository configurations
    c.execute(
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
    """
    )

    conn.commit()
    conn.close()
except sqlite3.Error as e:
    sys.exit(f"Database error: {e}")


def get_db():
    """
    Retrieves a SQLite database connection for the current Flask application context.
    """
    if "db" not in g:
        g.db = sqlite3.connect(os.path.join(APP_NAME, "data.db"))
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):  # pylint: disable=unused-argument
    """
    Closes the database connection at the end of the Flask application context.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


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
    return cipher_suite.encrypt(secret.encode()).decode()


def decrypt_secret(encrypted_secret: str) -> str:
    """
    Decrypts a stored secret.

    Args:
        encrypted_secret (str): The encrypted secret string.

    Returns:
        str: The decrypted plaintext secret.
    """
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
        return hmac.compare_digest(plaintext_secret, stored_secret)
    except Exception:  # pylint: disable=broad-exception-caught
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
        return False

    try:
        sha_name, signature = signature_header.split("=", 1)
    except ValueError:
        return False

    if sha_name != "sha256":
        return False

    mac = hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256)
    expected_signature = mac.hexdigest()
    return hmac.compare_digest(expected_signature, signature)


def verify_discord_webhook(webhook_url: str) -> bool:
    """
    Verifies that a Discord webhook URL is valid and active.

    Args:
        webhook_url (str): The Discord webhook URL to verify.

    Returns:
        bool: True if the webhook is valid and active, False otherwise.
    """
    try:
        response = requests.get(webhook_url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
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
                return parts[0], parts[1]
    except Exception:  # pylint: disable=broad-exception-caught
        pass

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
        response = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=5,
        )

        if response.status_code == 200:
            data = response.json()
            return {
                "repo_id": data["id"],
                "repo_full_name": data["full_name"],
                "owner_id": data["owner"]["id"],
            }
    except requests.RequestException:
        pass

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

        payload = {
            "username": "GitHub Events Bot",
            "avatar_url": "https://cdn-icons-png.flaticon.com/512/616/616489.png",
            "embeds": [
                {
                    "author": {
                        "name": event_data["sender"]["login"],
                        "icon_url": event_data["sender"]["avatar_url"],
                        "url": event_data["sender"]["html_url"],
                    },
                    "title": (
                        f"[{event_data['repository']['full_name']}] "
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
        return True
    except (KeyError, requests.RequestException) as e:
        print(f"Error sending to Discord: {e}")
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
        return cursor.fetchone() is not None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
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
        db.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


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
        return dict(row) if row else None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None


# ============================================================================
# Web Routes
# ============================================================================


@app.route("/", methods=["GET"])
def index():
    """
    Serves the frontend HTML page.
    """
    try:
        return render_template("index.html")
    except Exception:  # pylint: disable=broad-exception-caught
        return jsonify(
            {
                "app": APP_NAME,
                "version": APP_VERSION,
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

    if event_type == "ping":
        return jsonify({"message": "Webhook received and verified"}), 200

    # Validate JSON payload
    if not request.is_json:
        return jsonify({"error": "Expected application/json"}), 400

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Malformed or empty JSON"}), 400

    # Extract repository information
    repo_id = data.get("repository", {}).get("id")
    if not repo_id:
        return jsonify({"error": "Missing repository.id"}), 400

    # Get repository configuration
    repo_config = get_repository_by_id(repo_id)
    if not repo_config:
        return jsonify({"error": "Repository not configured"}), 404

    # Validate webhook signature
    signature_header = request.headers.get("x-hub-signature-256")
    if not signature_header:
        return jsonify({"error": "Missing signature"}), 403

    # Decrypt secret and validate signature
    try:
        secret = decrypt_secret(repo_config["secret_encrypted"])
        if not verify_github_signature(secret, signature_header, request.data):
            return jsonify({"error": "Invalid signature"}), 403
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error validating signature: {e}")
        return jsonify({"error": "Signature validation failed"}), 403

    # Check if event type is supported
    if event_type not in ["star", "watch"]:
        return jsonify({"error": "Unsupported event type"}), 422

    # Check if this event type is enabled for this repository
    enabled_events = repo_config["enabled_events"].split(",")
    if event_type not in enabled_events:
        return (
            jsonify(
                {"message": f"{event_type} events not enabled for this repository"}
            ),
            200,
        )

    # Check action
    action = data.get("action")
    if action not in ("created", "started"):  # 'started' is for watch events
        return jsonify({"message": f"Action '{action}' not processed"}), 200

    # Get sender information
    sender_id = data.get("sender", {}).get("id")
    if sender_id is None:
        return jsonify({"error": "Missing sender ID"}), 400

    # Check if user has already triggered this event
    if not has_user_triggered_event_before(sender_id, repo_id, event_type):
        if send_discord_notification(
            repo_config["discord_webhook_url"], data, event_type
        ):
            add_user_event(sender_id, repo_id, event_type)
            return jsonify({"message": "Event processed and notification sent"}), 200
        return jsonify({"error": "Failed to send Discord notification"}), 500

    return jsonify({"message": "Event already processed for this user"}), 200


# ============================================================================
# API Routes for Frontend
# ============================================================================


@app.route("/api/generate-secret", methods=["GET"])
def api_generate_secret():
    """
    Generates a cryptographically secure random secret.
    """
    secret = secrets.token_urlsafe(32)
    return jsonify({"secret": secret}), 200


@app.route("/api/repositories", methods=["POST"])
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
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON payload"}), 400

    repo_url = data.get("repo_url", "").strip()
    secret = data.get("secret", "").strip()
    discord_webhook_url = data.get("discord_webhook_url", "").strip()
    enabled_events = data.get("enabled_events", "").strip()

    # Validate inputs
    if not all([repo_url, secret, discord_webhook_url, enabled_events]):
        return jsonify({"error": "Missing required fields"}), 400

    # Validate enabled events
    events = enabled_events.split(",")
    valid_events = {"star", "watch"}
    if not all(event in valid_events for event in events):
        return (
            jsonify({"error": "Invalid event types. Must be 'star' and/or 'watch'"}),
            400,
        )

    # Extract owner and repo from URL
    repo_info = extract_repo_info_from_url(repo_url)
    if not repo_info:
        return jsonify({"error": "Invalid GitHub repository URL"}), 400

    owner, repo_name = repo_info

    # Fetch repository data from GitHub
    github_data = fetch_repo_data_from_github(owner, repo_name)
    if not github_data:
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
        db.commit()
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
        return jsonify({"error": "Repository already exists in the database"}), 409
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {e}"}), 500


@app.route("/api/repositories/verify", methods=["POST"])
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
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON payload"}), 400

    repo_url = data.get("repo_url", "").strip()
    secret = data.get("secret", "").strip()
    discord_webhook_url = data.get("discord_webhook_url", "").strip()

    if not all([repo_url, secret, discord_webhook_url]):
        return jsonify({"error": "Missing required fields"}), 400

    # Extract owner and repo from URL
    repo_info = extract_repo_info_from_url(repo_url)
    if not repo_info:
        return jsonify({"error": "Invalid GitHub repository URL"}), 400

    owner, repo_name = repo_info

    # Fetch repository data from GitHub
    github_data = fetch_repo_data_from_github(owner, repo_name)
    if not github_data:
        return jsonify({"error": "Could not fetch repository data from GitHub"}), 400

    # Get repository from database
    repo_config = get_repository_by_id(github_data["repo_id"])
    if not repo_config:
        return jsonify({"error": "Repository not found in database"}), 404

    # Verify secret and webhook URL
    if not verify_secret(secret, repo_config["secret_encrypted"]):
        return jsonify({"error": "Invalid secret"}), 403

    if repo_config["discord_webhook_url"] != discord_webhook_url:
        return jsonify({"error": "Invalid Discord webhook URL"}), 403

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
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON payload"}), 400

    old_secret = data.get("old_secret", "").strip()
    enabled_events = data.get("enabled_events", "").strip()

    if not old_secret or not enabled_events:
        return jsonify({"error": "Missing required fields"}), 400

    # Validate enabled events
    events = enabled_events.split(",")
    valid_events = {"star", "watch"}
    if not all(event in valid_events for event in events):
        return jsonify({"error": "Invalid event types"}), 400

    # Get repository from database
    repo_config = get_repository_by_id(repo_id)
    if not repo_config:
        return jsonify({"error": "Repository not found"}), 404

    # Verify old secret
    if not verify_secret(old_secret, repo_config["secret_encrypted"]):
        return jsonify({"error": "Invalid secret"}), 403

    # Prepare updates
    updates = []
    params = []

    new_secret = data.get("new_secret", "").strip()
    if new_secret:
        updates.append("secret_encrypted = ?")
        params.append(encrypt_secret(new_secret))

    discord_webhook_url = data.get("discord_webhook_url", "").strip()
    if discord_webhook_url:
        if not verify_discord_webhook(discord_webhook_url):
            return jsonify({"error": "Discord webhook URL is invalid or inactive"}), 400
        updates.append("discord_webhook_url = ?")
        params.append(discord_webhook_url)

    updates.append("enabled_events = ?")
    params.append(enabled_events)

    updates.append("updated_at = CURRENT_TIMESTAMP")

    params.append(repo_id)

    # Update database
    db = get_db()
    try:
        db.execute(
            f"UPDATE repositories SET {', '.join(updates)} WHERE repo_id = ?", params
        )
        db.commit()
        return jsonify({"message": "Repository updated successfully"}), 200
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {e}"}), 500


@app.route("/api/repositories/<int:repo_id>", methods=["DELETE"])
def api_delete_repository(repo_id):
    """
    Deletes a repository configuration.

    Expected JSON payload:
    {
        "secret": "webhook_secret"
    }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON payload"}), 400

    secret = data.get("secret", "").strip()
    if not secret:
        return jsonify({"error": "Missing secret"}), 400

    # Get repository from database
    repo_config = get_repository_by_id(repo_id)
    if not repo_config:
        return jsonify({"error": "Repository not found"}), 404

    # Verify secret
    if not verify_secret(secret, repo_config["secret_encrypted"]):
        return jsonify({"error": "Invalid secret"}), 403

    # Delete from database
    db = get_db()
    try:
        db.execute("DELETE FROM repositories WHERE repo_id = ?", (repo_id,))
        db.commit()
        return jsonify({"message": "Repository deleted successfully"}), 200
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {e}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
