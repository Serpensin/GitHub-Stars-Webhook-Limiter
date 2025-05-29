import json
import os
from platform import release
import sys
import sqlite3
import requests
import hashlib
import hmac
import sentry_sdk
from flask import Flask, request, g
from sentry_sdk.integrations.flask import FlaskIntegration
from dotenv import load_dotenv



load_dotenv()
APP_NAME = 'GitHub Stars Limiter'
APP_VERSION = '1.0.0'

sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN"),
    send_default_pii=True,
    traces_sample_rate=1.0,
    profile_session_sample_rate=1.0,
    profile_lifecycle="trace",
    environment="Production",
    release=f"{APP_NAME}@{APP_VERSION}",
)

try:
    with open('config.json', encoding='utf-8') as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    sys.exit(f"Configuration file 'config.json' not found.")


app = Flask(__name__)


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
    return f"{APP_NAME} v{APP_VERSION} is running!", 200, {'Content-Type': 'text/plain; charset=utf-8'}




@app.route('/send', methods=['POST'])
def foo():
    if not request.is_json:
        return "Invalid JSON", 400, {'Content-Type': 'text/plain; charset=utf-8'}
    data = request.get_json()
    repo_data = getRepoData(data['repository']['full_name'])
    if not repo_data:
        return "Repository not found in configuration", 404, {'Content-Type': 'text/plain; charset=utf-8'}
    if not isValidSecret(repo_data['secret'], request):
        return "Invalid secret", 403, {'Content-Type': 'text/plain; charset=utf-8'}
    if not isStarEvent(request.headers):
        return "Not a star event", 400, {'Content-Type': 'text/plain; charset=utf-8'}
    if not isActionCreated(request.json):
        return "Action is not created", 400, {'Content-Type': 'text/plain; charset=utf-8'}
    if not hasUserStaredBefore(data['sender']['id'], data['repository']['full_name']):
        if send_to_discord(repo_data['discord_webhook_url'], data):
            addStarredRepo(data['sender']['id'], data['repository']['full_name'])


    return "Event processed successfully", 200, {'Content-Type': 'text/plain; charset=utf-8'}







def isStarEvent(data) -> bool:
    if 'x-github-event' not in data:
        return False
    if data['x-github-event'] == 'star':
        return True
    return False

def isActionCreated(data) -> bool:
    if 'action' not in data:
        return False
    if data['action'] == 'created':
        return True
    return False

def getRepoData(repo_name: str) -> dict | None:
    return CONFIG.get("repositories", {}).get(repo_name)

def hasUserStaredBefore(github_user_id: int, repository: str) -> bool:
    try:
        c.execute('SELECT 1 FROM starred_repo WHERE github_user_id = ? AND repository = ?', (github_user_id, repository))
        return c.fetchone() is not None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

def isValidSecret(secret, flask_request):
    header_signature = flask_request.headers.get('x-hub-signature-256')
    if not header_signature:
        return False

    sha_name, signature = header_signature.split('=')
    if sha_name != 'sha256':
        return False

    mac = hmac.new(secret.encode(), msg=flask_request.data, digestmod=hashlib.sha256)
    expected_signature = mac.hexdigest()
    return hmac.compare_digest(expected_signature, signature)



def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(os.path.join(APP_NAME, 'data.db'))
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()



def hasUserStaredBefore(github_user_id: int, repository: str) -> bool:
    db = get_db()
    try:
        c = db.cursor()
        c.execute('SELECT 1 FROM starred_repo WHERE github_user_id = ? AND repository = ?', (github_user_id, repository))
        return c.fetchone() is not None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

def addStarredRepo(github_user_id: int, repository: str):
    db = get_db()
    try:
        c = db.cursor()
        c.execute('INSERT INTO starred_repo (github_user_id, repository) VALUES (?, ?)', (github_user_id, repository))
        db.commit()
    except sqlite3.IntegrityError:
        print(f"User {github_user_id} has already starred {repository}.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def send_to_discord(url: str, data: dict) -> bool:
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
    try:
        requests.post(url, json=payload)
        return True
    except requests.RequestException as e:
        print(f"Error sending to Discord: {e}")
        return False

















if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
    
    