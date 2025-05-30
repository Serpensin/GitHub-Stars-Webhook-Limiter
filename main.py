import hashlib
import hmac
import json
import os
import sqlite3
import sys

import requests
import sentry_sdk
from dotenv import load_dotenv
from flask import Flask, Request, g, jsonify, request

"""
GitHub Stars Limiter

A Flask application that listens for GitHub 'star' webhook events, validates them,
and sends notifications to Discord webhooks if a user stars a repository for the first time.
It uses SQLite for persistence and supports Sentry for error monitoring.

Main features:
- Validates GitHub webhook secrets.
- Prevents duplicate notifications for the same user/repo pair.
- Sends Discord notifications for new stars.
- Provides a health check endpoint.
"""



load_dotenv()
APP_NAME = 'GitHub_Stars_Limiter'
APP_VERSION = '1.0.0'

"""
Initializes Sentry SDK for error monitoring and performance tracing.

- dsn: The Sentry DSN, loaded from environment variables.
- send_default_pii: Enables sending personally identifiable information.
- traces_sample_rate: Sets the sample rate for performance traces.
- profile_session_sample_rate: Sets the sample rate for profiling sessions.
- profile_lifecycle: Sets the profile lifecycle mode.
- environment: Sets the environment name for Sentry.
- release: Sets the release version for Sentry.

This configuration enables comprehensive error and performance monitoring for the Flask application.
"""
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

try:
    with open('config.json', encoding='utf-8') as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    sys.exit(f"Configuration file 'config.json' not found.")

os.makedirs(APP_NAME, exist_ok=True)

try:
    conn = sqlite3.connect(os.path.join(APP_NAME, 'data.db'))
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS starred_repo (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        github_user_id INTEGER NOT NULL,
        repository TEXT NOT NULL,
        UNIQUE(github_user_id, repository)
    )
    ''')
    conn.commit()
    conn.close()
except sqlite3.Error as e:
    sys.exit(f"Database error: {e}")


@app.route('/', methods=['GET'])
def index():
    """
    Health check endpoint for the GitHub Stars Limiter application.

    Returns a JSON response containing the application name, version, and status.
    This endpoint can be used to verify that the service is running.

    Returns:
        Response: A Flask JSON response with app metadata and status.
    """
    return jsonify_success({
        "app": APP_NAME,
        "version": APP_VERSION,
        "status": "running"
    })

@app.route('/send', methods=['POST'])
def handle_star_event():
    """
    Handles incoming GitHub 'star' webhook events.

    This endpoint processes POST requests containing GitHub webhook payloads for 'star' events.
    It performs the following steps:
    - Validates that the request contains JSON data.
    - Parses and validates the payload structure.
    - Checks that the repository exists in the configuration.
    - Validates the webhook secret using HMAC.
    - Ensures the event is a 'star' event and the action is 'created'.
    - Checks if the user has already starred the repository to prevent duplicate notifications.
    - Sends a notification to the configured Discord webhook if this is the user's first star for the repository.
    - Records the star event in the database.

    Returns:
        Response: A Flask JSON response indicating success or the specific error encountered.
    """
    if not request.is_json:
        return jsonify_error("Expected application/json")

    data = request.get_json(silent=True)
    if not data:
        return jsonify_error("Malformed or empty JSON")

    repo_full_name = data.get('repository', {}).get('full_name')
    if not repo_full_name:
        return jsonify_error("Missing 'repository.full_name'")

    repo_data = getRepoData(repo_full_name)
    if not repo_data:
        return jsonify_error("Repository not found in config", 404)

    if not isValidSecret(repo_data['secret'], request):
        return jsonify_error("Invalid secret", 403)

    if not isStarEvent(request.headers):
        return jsonify_error("Not a star event", 422)

    if not isActionCreated(data):
        return jsonify_error("Action is not created", 422)

    sender_id = data.get('sender', {}).get('id')
    if sender_id is None:
        return jsonify_error("Missing sender ID")

    if not hasUserStaredBefore(sender_id, repo_full_name):
        if send_to_discord(repo_data['discord_webhook_url'], data):
            addStarredRepo(sender_id, repo_full_name)

    return jsonify_success("Event processed successfully")



def jsonify_error(message: str, status_code: int = 400):
    """
    Returns a standardized JSON error response.

    Args:
        message (str): The error message to include in the response.
        status_code (int, optional): The HTTP status code for the response. Defaults to 400.

    Returns:
        Response: A Flask JSON response object with the error message and status code.
    """
    response = jsonify({"error": message})
    response.status_code = status_code
    return response

def jsonify_success(payload: dict | str = "OK", status_code: int = 200):
    """
    Returns a standardized JSON success response.

    Args:
        payload (dict | str, optional): The data to include in the response. If a dictionary is provided,
            it will be used as the JSON response body. If a string is provided, it will be wrapped in a
            dictionary with the key 'message'. Defaults to "OK".
        status_code (int, optional): The HTTP status code for the response. Defaults to 200.

    Returns:
        Response: A Flask JSON response object with the provided payload and status code.
    """
    if isinstance(payload, dict):
        response = jsonify(payload)
    else:
        response = jsonify({"message": payload})
    response.status_code = status_code
    return response



def get_db():
    """
    Retrieves a SQLite database connection for the current Flask application context.

    This function checks if a database connection already exists in the Flask `g` context object.
    If not, it creates a new connection to the application's SQLite database file, sets the row
    factory to return rows as dictionaries, and stores the connection in `g`. This ensures that
    each request uses a single database connection, which is properly closed at the end of the request.

    Returns:
        sqlite3.Connection: The SQLite database connection for the current request context.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(os.path.join(APP_NAME, 'data.db'))
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    """
    Closes the database connection at the end of the Flask application context.

    This function is registered as a Flask teardown callback. It removes the database
    connection from the Flask `g` context object and closes it if it exists. This ensures
    that each request properly cleans up its database resources, preventing resource leaks.

    Args:
        exception (Exception, optional): An exception raised during the request, if any.
            Defaults to None.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()



def isStarEvent(data: dict) -> bool:
    """
    Determines if the incoming GitHub webhook event is a 'star' event.

    Args:
        data (dict): The request headers or data containing the 'x-github-event' key.

    Returns:
        bool: True if the event is a 'star' event, False otherwise.
    """
    return data.get('x-github-event') == 'star'

def isActionCreated(data: dict) -> bool:
    """
    Checks if the GitHub webhook event action is 'created'.

    Args:
        data (dict): The webhook event payload.

    Returns:
        bool: True if the action is 'created', False otherwise.
    """
    return data.get('action') == 'created'

def getRepoData(repo_name: str) -> dict | None:
    """
    Retrieves the configuration data for a given repository name.

    Args:
        repo_name (str): The full name of the repository (e.g., 'owner/repo').

    Returns:
        dict | None: The configuration dictionary for the repository if found, otherwise None.
    """
    return CONFIG.get("repositories", {}).get(repo_name)

def hasUserStaredBefore(github_user_id: int, repository: str) -> bool:
    """
    Checks if a GitHub user has already starred a specific repository.

    This function queries the 'starred_repo' table in the SQLite database to determine
    whether a record exists for the given GitHub user ID and repository name. It is used
    to prevent duplicate notifications for the same user/repository pair.

    Args:
        github_user_id (int): The unique ID of the GitHub user.
        repository (str): The full name of the repository (e.g., 'owner/repo').

    Returns:
        bool: True if the user has already starred the repository, False otherwise.
    """
    db = get_db()
    try:
        c = db.execute(
            'SELECT 1 FROM starred_repo WHERE github_user_id = ? AND repository = ? LIMIT 1',
            (github_user_id, repository)
        )
        return c.fetchone() is not None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

def isValidSecret(secret: str, flask_request: Request) -> bool:
    """
    Validates the GitHub webhook secret using HMAC SHA-256.

    This function checks the 'x-hub-signature-256' header in the incoming Flask request,
    splits it to extract the hash algorithm and signature, and verifies that the algorithm
    is 'sha256'. It then computes the HMAC SHA-256 digest of the request body using the
    provided secret and compares it to the signature from the header in a timing-safe way.

    Args:
        secret (str): The webhook secret configured for the repository.
        flask_request (Request): The Flask request object containing headers and data.

    Returns:
        bool: True if the signature is valid and matches the computed HMAC, False otherwise.
    """
    header_signature = flask_request.headers.get('x-hub-signature-256')
    if not header_signature:
        return False

    try:
        sha_name, signature = header_signature.split('=', 1)
    except ValueError:
        return False
    if sha_name != 'sha256':
        return False

    mac = hmac.new(secret.encode('utf-8'), msg=flask_request.data, digestmod=hashlib.sha256)
    expected_signature = mac.hexdigest()
    return hmac.compare_digest(expected_signature, signature)



def addStarredRepo(github_user_id: int, repository: str):
    """
    Adds a record indicating that a GitHub user has starred a specific repository.

    This function inserts a new row into the 'starred_repo' table in the SQLite database
    for the given GitHub user ID and repository name. If the user has already starred the
    repository (i.e., the combination of user ID and repository is not unique), the insertion
    is ignored due to the 'INSERT OR IGNORE' clause.

    Args:
        github_user_id (int): The unique ID of the GitHub user who starred the repository.
        repository (str): The full name of the repository (e.g., 'owner/repo').

    Returns:
        None
    """
    try:
        db = get_db()
        db.execute(
            'INSERT OR IGNORE INTO starred_repo (github_user_id, repository) VALUES (?, ?)',
            (github_user_id, repository)
        )
        db.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def send_to_discord(url: str, data: dict) -> bool:
    """
    Sends a notification to a Discord webhook when a new star is added to a GitHub repository.

    This function constructs a Discord embed payload containing information about the user who starred
    the repository and the repository itself. It then sends this payload as a POST request to the specified
    Discord webhook URL. If the request is successful, the function returns True. If there is a KeyError
    (e.g., missing expected fields in the data) or a requests.RequestException (e.g., network error or
    non-2xx response), the function prints an error message and returns False.

    Args:
        url (str): The Discord webhook URL to which the notification will be sent.
        data (dict): The GitHub webhook event payload containing information about the star event.

    Returns:
        bool: True if the notification was sent successfully, False otherwise.
    """
    try:
        payload = {
            "components": [],
            "embeds": [
                {
                    "author": {
                        "name": data['sender']['login'],
                        "icon_url": data['sender']['avatar_url']
                    },
                    "title": f"[{data['repository']['full_name']}] New star added",
                    "url": data['repository']['html_url'],
                }
            ]
        }
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        return True
    except (KeyError, requests.RequestException) as e:
        print(f"Error sending to Discord: {e}")
        return False












if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
