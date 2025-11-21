# GitHub Events Limiter

A Flask application that listens for GitHub webhook events (star, watch), validates them,
and sends notifications to Discord webhooks if a user performs an action for the first time.
It supports both SQLite (default) and PostgreSQL databases, with Sentry for error monitoring.

## Features

- ✅ **Multiple Event Types**: Supports star and watch events
- ✅ **Webhook Secret Validation**: Validates GitHub webhook secrets using HMAC SHA-256
- ✅ **Encrypted Secrets**: Secrets are encrypted at rest for security
- ✅ **Deduplication**: Prevents duplicate notifications for the same user/repo/event combination
- ✅ **Discord Notifications**: Sends formatted embeds to Discord webhooks
- ✅ **Web Interface**: Easy-to-use front-end for repository management
- ✅ **API Key Authentication**: Secure programmatic access with Argon2id-hashed API keys
- ✅ **Admin Panel**: Password-protected interface for API key management, jetzt mit Pagination, direkter Seitenwahl, Such- und Filterfunktionen (inkl. dynamischer Berechtigungsfilter)
- ✅ **Database Support**: SQLite (default) or PostgreSQL
- ✅ **Repository ID Tracking**: Uses GitHub repository and owner IDs for resilience against name changes
- ✅ **Webhook Verification**: Responds to GitHub's ping event for webhook verification
- ✅ **Health Check**: Provides monitoring endpoint
- ✅ **Sentry Integration**: Optional error tracking and performance monitoring


## New in v1.4.0

- 🚀 **Admin Panel Pagination & Advanced Search**: API-Key-Übersicht jetzt mit Seitenwahl, direktem Seitenwechsel, Such- und Filterfunktionen (Name, Typ, Status, Rate Limit, dynamische Berechtigungen, Erstellungsdatum)
- 🚀 **Dynamischer Berechtigungsfilter**: Filtere API-Keys nach einzelnen oder mehreren Berechtigungen (bitweise, dynamisch generiert)
- 🚀 **Verbesserte Statistikanzeige**: Zeigt aktive/admin Keys, Ladeverhalten optimiert
- 🚀 **OpenAPI & Doku aktualisiert**: Alle neuen Filter- und Pagination-Parameter dokumentiert, Try-Page unterstützt neue Features
- 🚀 **UX-Verbesserungen**: Goto-Page-Eingabe nur sichtbar, wenn mehr als eine Seite vorhanden ist; Filter und Pagination sind reaktiv

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

**Choose Your Database:**

**Option A: SQLite (Default - Easiest Setup)**
```bash
# Edit docker-compose.yml with your environment variables
docker-compose up -d
```

**Option B: PostgreSQL**

You have two options for PostgreSQL:

1. **External PostgreSQL Server** (Recommended for Production)
   ```bash
   # Set PostgreSQL environment variables in .env file:
   # POSTGRES_HOST=your-postgres-host
   # POSTGRES_PORT=5432
   # POSTGRES_DB=starlimiter
   # POSTGRES_USER=starlimiter
   # POSTGRES_PASSWORD=your_secure_password
   
   docker-compose up -d
   ```

2. **Embedded PostgreSQL** (Development/Testing)
   ```bash
   # Uses the docker-compose.postgresql.yml with embedded PostgreSQL
   docker-compose -f docker-compose.postgresql.yml up -d
   ```

**IMPORTANT:** Docker's `--env-file` does not properly handle `$` symbols in Argon2 hashes. Use docker-compose or the methods below.

**Manual Docker with Environment Variables:**
```bash
# SQLite version
docker build -t github-events-limiter .
docker run -d -p 5000:5000 \
  -v $(pwd)/GitHub_Events_Limiter:/app/GitHub_Events_Limiter \
  -e ENCRYPTION_KEY="your-encryption-key" \
  -e ADMIN_PASSWORD_HASH='$argon2id$v=19$m=65536,t=3,p=4$...' \
  -e FLASK_SECRET_KEY="your-flask-secret" \
  -e SENTRY_DSN="your-sentry-dsn" \
  github-events-limiter

# PostgreSQL version (with embedded PostgreSQL server)
docker build -f Dockerfile.postgresql -t github-events-limiter:postgresql .
docker run -d -p 5000:5000 \
  -v postgres_data:/var/lib/postgresql/data \
  -e ENCRYPTION_KEY="your-encryption-key" \
  -e ADMIN_PASSWORD_HASH='$argon2id$v=19$m=65536,t=3,p=4$...' \
  -e FLASK_SECRET_KEY="your-flask-secret" \
  -e SENTRY_DSN="your-sentry-dsn" \
  github-events-limiter:postgresql
```

**Note:** PostgreSQL version uses an internal default password. PostgreSQL port is not exposed outside the container for security.

**Available Docker Images:**
- `ghcr.io/serpensin/github-stars-webhook-limiter:latest` - SQLite version
- `ghcr.io/serpensin/github-stars-webhook-limiter:postgresql` - PostgreSQL version (embedded server)

#### Manual Installation

```bash
# Install dependencies (includes PostgreSQL support via CustomModules[databasehandler])
pip install -r requirements.txt

# Run the application
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

# Database Configuration (Optional - defaults to SQLite)
# For PostgreSQL, set ALL of these environment variables:
# POSTGRES_HOST=localhost                    # PostgreSQL server hostname
# POSTGRES_PORT=5432                         # PostgreSQL server port (default: 5432)
# POSTGRES_DB=starlimiter                    # PostgreSQL database name
# POSTGRES_USER=starlimiter                  # PostgreSQL username
# POSTGRES_PASSWORD=your_secure_password     # PostgreSQL password

# If ANY PostgreSQL variable is missing, SQLite will be used as fallback
# SQLite database will be stored at: GitHub_Events_Limiter/data.db
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
- `GET /license` - View license information
- `GET /health` - Health check endpoint for monitoring (returns JSON with app and database status)

### Webhook
- `POST /webhook` - GitHub webhook endpoint (handles star, watch, ping events)

### Repository Management API (Protected)
**Authentication Required**: These endpoints require either:
- Same-origin Referer header (automatic when using the web interface), OR
- API key via `Authorization: Bearer <api_key>` header with appropriate permissions

#### Repository Operations
- `POST /api/repositories` - Add new repository configuration (requires `repositories-add` permission)
- `PATCH /api/repositories` - Update repository configuration (requires `repositories-update` permission)
- `DELETE /api/repositories` - Delete repository configuration (requires `repositories-delete` permission)
- `POST /api/repositories/verify` - Verify repository credentials for editing (requires `repositories-verify` permission)

#### Utilities
- `GET /api/generate-secret` - Generate secure random secret (44 chars) (requires `generate-secret` permission)
- `GET /api/events` - List all available event types (star, watch) (requires `events-list` permission)

#### Permissions API
- `GET /api/permissions` - List all available permissions with values (requires `permissions-list` permission)
- `POST /api/permissions/calculate` - Calculate permission bitmap from list (requires `permissions-calculate` permission)
- `POST /api/permissions/decode` - Decode permission bitmap to list (requires `permissions-decode` permission)

### Admin API (Password Protected)
**Authentication Required**: Session-based authentication via admin panel login

#### Authentication
- `POST /admin/api/login` - Authenticate with admin password
- `POST /admin/api/logout` - End admin session

#### API Key Management
- `GET /admin/api/keys` - List all API keys (unterstützt Pagination, Such- und Filterparameter, dynamische Berechtigungsfilter)
  - `POST /admin/api/keys` - Create new API key
  - `PATCH /admin/api/keys/<key_id>` - Update API key (name, permissions, rate limit)
  - `DELETE /admin/api/keys/<key_id>` - Delete API key
  - `POST /admin/api/keys/<key_id>/toggle` - Activate/deactivate API key
  - `POST /admin/api/keys/bulk` - Bulk operations (activate, deactivate, delete multiple keys)

#### Repository Management (Admin Panel)
- `GET /admin/api/repositories` - List all registered repositories with pagination and filtering
  - Query Parameters:
    - `page`: Page number (default 1)
    - `per_page`: Items per page (10, 25, 50, 100, -1 for all)
    - `name`: Filter by repository name (partial match)
    - `events`: Filter by enabled events ("star", "watch", "both")
- `PATCH /admin/api/repositories/<repo_id>` - Update repository (admin bypass - no secret needed)
  - Update Discord webhook URL, enabled events, or generate new webhook secret
  - Secrets are always displayed encrypted in the admin panel
- `DELETE /admin/api/repositories/<repo_id>` - Delete repository (admin bypass - no secret needed)

**Note**: Admin panel repository management bypasses webhook secret verification for convenience and security.


**API key pagination & filter parameters (GET /admin/api/keys):**

| Parameter         | Type     | Description                                                                 |
|-------------------|----------|-----------------------------------------------------------------------------|
| `page`            | int      | Page number (1-based)                                                       |
| `per_page`        | int      | Items per page                                                              |
| `search`          | string   | Search by name                                                              |
| `type`            | string   | Filter by key type (`user`, `admin`, etc.)                                  |
| `status`          | string   | Filter by status (`active`, `inactive`)                                     |
| `ratelimit`       | int      | Filter by rate limit                                                        |
| `created_from`    | string   | Filter by creation date (ISO 8601, from)                                    |
| `created_to`      | string   | Filter by creation date (ISO 8601, to)                                      |
| `permissions`     | int[]    | Filter by any permissions (bitwise, dynamic, AND combination)               |

All filters can be combined. The response includes `total`, `page`, `per_page`, `pages`, and the filtered keys.

#### Logs
- `GET /admin/api/logs/list` - List available log files
- `GET /admin/api/logs` - View log file contents
- `GET /admin/api/logs/download` - Download log file

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

### Admin API Keys

**Admin keys have special privileges:**
- ✅ **Bypass Secret Verification**: Can modify or delete ANY repository without knowing the webhook secret
- ✅ **Full API Access**: Unrestricted access to all API endpoints
- ✅ **No Rate Limiting**: Admin keys ignore rate limit restrictions
- ✅ **Admin Panel Access**: Can manage API keys and view system logs

**Use admin keys for:**
- Repository cleanup and maintenance
- Automated testing and CI/CD pipelines
- System administration tasks
- Bulk repository operations

**Security Note**: Admin keys are powerful - treat them like root passwords. Only create them when necessary and store them securely.

## Security Features

### Required Secrets Management

The application requires three secrets to be set before starting:

1. **ENCRYPTION_KEY**: Fernet key for encrypting repository secrets in the database
2. **ADMIN_PASSWORD_HASH**: Argon2id hash for admin authentication
3. **FLASK_SECRET_KEY**: Secret key for Flask session management

**Generate all secrets at once:**

```bash
python ./scripts/generate_required_secrets.py
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

## Monitoring & Health Checks

The application provides a comprehensive health check endpoint for monitoring and container orchestration:

- **Endpoint**: `/health`
- **Response**: JSON with application status, version, and database connectivity
- **HTTP Status Codes**:
  - `200 OK` - Application and database are healthy
  - `503 Service Unavailable` - Database is unreachable or unhealthy

**Response Format:**

```json
{
  "status": "healthy",
  "app": "GitHub Events Limiter",
  "version": "2.4.2",
  "database": {
    "type": "sqlite",
    "status": "healthy"
  }
}
```

If the database is unhealthy:

```json
{
  "status": "unhealthy",
  "app": "GitHub Events Limiter",
  "version": "2.4.2",
  "database": {
    "type": "postgresql",
    "status": "unhealthy",
    "error": "connection refused"
  }
}
```

**Docker Healthcheck Configuration:**

The included `docker-compose.yml` files configure automatic health checks using a custom User-Agent header:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "-A", "Healthcheck", "http://localhost:5000/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 20s
```

**Logging Behavior:**

- Health checks with `User-Agent: Healthcheck` are logged at **DEBUG** level
- Other requests to `/health` are logged at **INFO** level
- Database connectivity failures are always logged at **ERROR** level
- This allows filtering health check noise while monitoring real traffic

**Custom Monitoring:**

To reduce log verbosity in your monitoring tools, set the User-Agent header:

```bash
curl -A "Healthcheck" http://localhost:5000/health
```

**Kubernetes Probes:**

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 5000
    httpHeaders:
    - name: User-Agent
      value: Healthcheck
  initialDelaySeconds: 20
  periodSeconds: 30
  timeoutSeconds: 10
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health
    port: 5000
    httpHeaders:
    - name: User-Agent
      value: Healthcheck
  initialDelaySeconds: 10
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
```

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
# Format imports
py -m isort .

# Format code
py -m black .

# Check code style
py -m pip install flake8-pyproject
py -m flake8 .

# Run static analysis
py -m pylint *.py routes modules --fail-under=10.0
```

### Running Tests

The project includes a comprehensive test suite. See [Tests/README.md](Tests/README.md) for detailed documentation.

**Prerequisites:**
- Running application instance (Docker or manual)
- Admin password configured

**Run all tests:**
```bash
python -m unittest discover Tests -v
```

**Run specific test file:**
```bash
python -m unittest Tests.test_authentication -v
python -m unittest Tests.test_api_keys -v
python -m unittest Tests.test_all_endpoints -v
```

**Test coverage:**
- ✅ Authentication & Authorization
- ✅ API Key Management
- ✅ Permission System
- ✅ Rate Limiting
- ✅ All API Endpoints
- ✅ Input Validation
- ✅ Error Handling

### File Structure

```
.
├── main.py                  # Main application file
├── requirements.txt         # Python dependencies
├── .env                     # Environment variables (not in git)
├── pyproject.toml           # Tool configuration (black, flake8, pylint, isort)
├── modules/                 # Custom Python modules
│   ├── AuthenticationHandler.py
│   ├── BitmapHandler.py
│   ├── DatabaseHandler.py
│   ├── LogHandler.py
│   └── SecurityHandler.py
├── routes/                  # Flask route blueprints
│   ├── admin.py             # Admin panel routes
│   ├── api.py               # API routes
│   └── web.py               # Web interface routes
├── templates/               # HTML templates
│   ├── index.html           # Main web interface
│   ├── admin.html           # Admin panel
│   └── docs.html            # API documentation
├── static/                  # Static assets
│   ├── style.css            # Main styles
│   ├── admin.css            # Admin panel styles
│   ├── script.js            # Frontend JavaScript
│   └── admin.js             # Admin panel JavaScript
├── Tests/                   # Test suite
│   ├── README.md            # Testing documentation
│   ├── test_authentication.py
│   ├── test_api_keys.py
│   └── test_all_endpoints.py
├── GitHub_Events_Limiter/   # Application data
│   ├── data.db              # SQLite database (created on first run)
│   └── logs/                # Application logs
├── Dockerfile               # Docker configuration
├── docker-compose.yml       # Docker Compose configuration
└── README.md                # This file
```

## Contributing

Contributions welcome! Please open an issue or pull request on GitHub.

### Development Guidelines

- Follow PEP 8 style guide
- Run pylint and flake8 before committing

