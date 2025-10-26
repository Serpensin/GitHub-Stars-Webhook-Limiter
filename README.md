# GitHub Events Limiter

A Flask application that listens for GitHub webhook events (star, watch), validates them,
and sends notifications to Discord webhooks if a user performs an action for the first time.
It uses SQLite for persistence and supports Sentry for error monitoring.

## Features

- ✅ **Multiple Event Types**: Supports star and watch events
- ✅ **Webhook Secret Validation**: Validates GitHub webhook secrets using HMAC SHA-256
- ✅ **Encrypted Secrets**: Secrets are encrypted at rest for security
- ✅ **Deduplication**: Prevents duplicate notifications for the same user/repo/event combination
- ✅ **Discord Notifications**: Sends formatted embeds to Discord webhooks
- ✅ **Web Interface**: Easy-to-use front-end for repository management
- ✅ **API Key Authentication**: Secure programmatic access with Argon2id-hashed API keys
- ✅ **Admin Panel**: Password-protected interface for API key management
- ✅ **SQLite Database**: All configuration stored in SQLite (no config files needed)
- ✅ **Repository ID Tracking**: Uses GitHub repository and owner IDs for resilience against name changes
- ✅ **Webhook Verification**: Responds to GitHub's ping event for webhook verification
- ✅ **Health Check**: Provides monitoring endpoint
- ✅ **Sentry Integration**: Optional error tracking and performance monitoring

## New in v2.0.0

- 🎉 **Watch Event Support**: Now tracks first-time watchers in addition to stars
- 🎉 **Web UI**: Manage repositories through a beautiful web interface
- 🎉 **API Key System**: Generate and manage API keys for programmatic access
- 🎉 **Admin Panel**: Secure admin interface with Argon2id password hashing (like Vaultwarden)
- 🎉 **Protected API Routes**: Web interface or API key required - no public API access
- 🎉 **No Config Files**: All configuration moved to SQLite database with encrypted secrets
- 🎉 **Secure Secret Generation**: Built-in secure random secret generator
- 🎉 **Discord Webhook Verification**: Validates Discord webhooks before saving
- 🎉 **GitHub API Integration**: Automatically fetches repository metadata (ID, owner ID)
- 🎉 **CRUD Operations**: Add, update, verify, and delete repository configurations
- 🎉 **Encrypted Secret Storage**: Secrets encrypted with Fernet for security

## Setup Instructions

### 1. Installation

#### Using Docker (Recommended)

**IMPORTANT:** Docker's `--env-file` does not properly handle `$` symbols in Argon2 hashes. Use one of these methods:

**Option 1: Using docker-compose (Recommended)**
```bash
# Edit docker-compose.yml with your environment variables
docker-compose up -d
```

**Option 2: Using -e flags**
```bash
docker build -t github-events-limiter .
docker run -d -p 5000:5000 \
  -v $(pwd)/GitHub_Events_Limiter:/app/GitHub_Events_Limiter \
  -e ENCRYPTION_KEY="your-encryption-key" \
  -e ADMIN_PASSWORD_HASH='$argon2id$v=19$m=65536,t=3,p=4$...' \
  -e FLASK_SECRET_KEY="your-flask-secret" \
  -e SENTRY_DSN="your-sentry-dsn" \
  github-events-limiter
```

#### Manual Installation

```bash
pip install -r requirements.txt
python main.py
```

**Important:** The application will NOT start without valid environment variables. See the next section for setup.

### 2. Environment Variables

Create a `.env` file with **ALL required secrets**:

```env
ENCRYPTION_KEY=your-encryption-key-here      # REQUIRED: Fernet key for encrypting secrets
ADMIN_PASSWORD_HASH=your-argon2-hash-here    # REQUIRED: Admin password hash (must be valid Argon2)
FLASK_SECRET_KEY=your-flask-secret-key-here  # REQUIRED: Flask session secret
SENTRY_DSN=your-sentry-dsn-here              # Optional: For error monitoring
```

**⚠️ IMPORTANT:** Do NOT use the placeholder values above! The application validates that:
1. All required variables are set (not empty)
2. Values are NOT placeholders from `.env.example` or `docker-compose.yml`
3. `ADMIN_PASSWORD_HASH` is a valid Argon2 hash format

If validation fails, the application will exit immediately with a detailed error message.


**Generate All Required Secrets:**

```bash
python generate_required_secrets.py
```

This will generate all three required secrets at once. Copy the output to your `.env` file or `docker-compose.yml`.

**Important Notes:**
- All three secrets (ENCRYPTION_KEY, ADMIN_PASSWORD_HASH, FLASK_SECRET_KEY) are **REQUIRED**
- Empty values will cause validation to fail
- Run `python generate_required_secrets.py --check` to validate your `.env` file
- The application will **exit immediately** if any secret is missing
- Keep these secrets secure and backed up!
- Use different secrets for development and production

### 3. Add Repository via Web Interface

1. Open your browser to `http://localhost:5000` or `https://your-domain.com`
2. Click "Add Repository" tab
3. Fill in the form:
   - **Repository URL**: `https://github.com/owner/repo`
   - **Secret**: Click "Generate" to create a secure secret, then "Copy"
   - **Discord Webhook URL**: Your Discord webhook URL
   - **Events**: Select star and/or watch events
4. Click "Add Repository"

### 4. Configure GitHub Webhook

1. Go to your GitHub repository → **Settings** → **Webhooks** → **Add webhook**
2. Set **Payload URL** to: `https://your-domain.com/webhook`
3. Set **Content type** to: `application/json`
4. Paste your secret in the **Secret** field (the one you generated/copied in step 3)
5. Select individual events:
   - ☑️ **Stars** (if enabled)
   - ☑️ **Watches** (if enabled)
6. Ensure **Active** is checked
7. Click **Add webhook**
8. GitHub will send a ping event to verify the webhook - you should see a green checkmark

### 5. Test

Star or watch your repository to verify Discord notifications work!

## API Endpoints

### Web Interface
- `GET /` - Main web interface for repository management
- `GET /admin` - Admin panel for API key management (password protected)

### Webhook
- `POST /webhook` - GitHub webhook endpoint (handles star, watch, ping events)

### Repository Management API (Protected)
**Authentication Required**: These endpoints require either:
- Same-origin Referer header (automatic when using the web interface), OR
- API key via `Authorization: Bearer <api_key>` header

- `POST /api/repositories` - Add new repository configuration
- `POST /api/repositories/verify` - Verify repository credentials for editing
- `PUT /api/repositories/<repo_id>` - Update repository configuration
- `DELETE /api/repositories/<repo_id>` - Delete repository configuration
- `GET /api/generate-secret` - Generate secure random secret (44 chars)

### Admin API (Password Protected)
**Authentication Required**: Session-based authentication via admin panel login

- `POST /admin/api/login` - Authenticate with admin password
- `POST /admin/api/logout` - End admin session
- `GET /admin/api/keys` - List all API keys
- `POST /admin/api/keys` - Create new API key
- `DELETE /admin/api/keys/<key_id>` - Delete API key
- `POST /admin/api/keys/<key_id>/toggle` - Activate/deactivate API key

## API Authentication

### Web Interface Access
The web interface at `/` can access all repository management APIs directly without additional authentication. Access is restricted to same-origin requests via Referer header validation.

### Programmatic Access
For programmatic access (scripts, CI/CD, external tools), you need an API key:

1. **Access Admin Panel**: Navigate to `/admin` and log in with your admin password
2. **Generate API Key**: Create a new API key with a descriptive name
3. **Save Securely**: The key is only shown once - store it securely!
4. **Use in Requests**: Include the key in the Authorization header:

```bash
curl -X POST https://your-domain.com/api/repositories \
  -H "Authorization: Bearer your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo", ...}'
```
## Security Features

### Required Secrets Management

The application requires three secrets to be set before starting:

1. **ENCRYPTION_KEY**: Fernet key for encrypting repository secrets in the database
2. **ADMIN_PASSWORD_HASH**: Argon2id hash for admin authentication
3. **FLASK_SECRET_KEY**: Secret key for Flask session management

**Generate all secrets at once:**

```bash
python generate_required_secrets.py
```

The script will:
- Generate a secure Fernet encryption key
- Generate a secure Flask secret key (64-character hex)
- Prompt for admin password and create Argon2id hash
- Display all secrets ready to copy to `.env` or `docker-compose.yml`

**Check if secrets are configured:**

```bash
python generate_required_secrets.py --check
```

This will verify all required environment variables are set and exit with an error if any are missing.

**Manual generation (if needed):**

```bash
# ENCRYPTION_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# FLASK_SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# ADMIN_PASSWORD_HASH
python -c "from argon2 import PasswordHasher; ph = PasswordHasher(); print(ph.hash('your-password'))"
```

### Admin Password Setup

**Note:** Use `python generate_required_secrets.py` to generate all required secrets including the admin password hash.

**Note:** Use `python generate_required_secrets.py` to generate all required secrets including the admin password hash.

## Database Schema

### repositories Table
```sql
CREATE TABLE repositories (
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
```

### user_events Table
```sql
CREATE TABLE user_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    github_user_id INTEGER NOT NULL,
    repository_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    UNIQUE(github_user_id, repository_id, event_type)
)
```

### api_keys Table
```sql
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    is_active INTEGER DEFAULT 1
)
```

## Managing Repositories

### Update Configuration

1. Go to "Manage Repository" tab
2. Enter your repository URL, current secret, and current Discord webhook URL
3. Click "Verify & Load"
4. Update the fields you want to change:
- **New Secret**: Leave empty to keep current secret
   - **New Discord Webhook**: Leave empty to keep current webhook
   - **Events**: Select which events should trigger notifications
5. Click "Update Repository"

### Delete Repository

1. Follow the verification steps above
2. Click "Delete Repository"
3. Confirm the deletion

**Note**: Deleting a repository removes all configuration and event history for that repository.

## Security Notes

- **Secrets Storage**: Secrets are encrypted using Fernet (symmetric encryption) before storage
- **Encryption Key**: The `ENCRYPTION_KEY` must be kept secure and backed up - without it, secrets cannot be decrypted
- **Database Location**: `GitHub_Events_Limiter/data.db` - ensure this directory is backed up and secured
- **Webhook Verification**: Always use HTTPS in production to protect webhook secrets in transit
- **Discord Webhook Validation**: The app verifies Discord webhooks are active before saving
- **HMAC Signature Validation**: All GitHub webhook payloads are validated using HMAC SHA-256

## Troubleshooting

### GitHub webhook shows error
- Verify your secret matches exactly (case-sensitive)
- Check that the webhook URL is accessible from the internet (use HTTPS)
- Review the webhook delivery logs in GitHub Settings → Webhooks
- Ensure you selected the correct events (Stars and/or Watches)

### Discord notifications not received
- Verify the Discord webhook URL is correct and active
- Check the enabled events in your configuration match the GitHub webhook events
- Review application logs for errors: `docker logs <container-id>` or console output
- Test the Discord webhook manually with a curl command

### Repository name changed
- No action needed! The app uses repository IDs which persist across name changes
- The `repo_full_name` field will be outdated but the webhook will still work

### Encryption key lost
- If you lose the `ENCRYPTION_KEY`, you cannot decrypt stored secrets
- You will need to delete all repositories and re-add them with new secrets
- **Always backup your encryption key securely!**

### Application won't start
- Check that the `ENCRYPTION_KEY` is set in your `.env` file
- Ensure all dependencies are installed: `pip install -r requirements.txt`
- Verify the database file has write permissions

## Development

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run in debug mode
python main.py
```

The application will be available at `http://localhost:5000`

### Running Linters

```bash
# Check code style
isort main.py
black main.py
flake8 main.py
pylint main.py --fail-under=10.0
```

### File Structure

```
.
├── main.py          # Main application file
├── requirements.txt    # Python dependencies
├── .env          # Environment variables (not in git)
├── templates/
│   └── index.html  # Web interface
├── static/
│   ├── style.css    # Styles
│   └── script.js       # Frontend JavaScript
├── GitHub_Events_Limiter/
│   └── data.db         # SQLite database (created on first run)
├── Dockerfile   # Docker configuration
└── README.md         # This file
```

## Migration from v1.x

If you're upgrading from v1.x (config.json based):

1. **Backup your data**: Save your old `config.json` and `data.db`
2. **Note your secrets**: You'll need to re-add repositories with their secrets
3. **Set encryption key**: Generate and save an encryption key
4. **Use Web UI**: Add each repository through the new web interface
5. **Update webhooks**: No changes needed in GitHub if the webhook URL is the same

The old `starred_repo` table data will be preserved (user stars history).

## License

MIT License - See repository for details

## Contributing

Contributions welcome! Please open an issue or pull request on GitHub.

### Development Guidelines

- Follow PEP 8 style guide
- Run pylint and flake8 before committing

