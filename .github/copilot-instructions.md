# GitHub Events Limiter - AI Coding Assistant Instructions

## Project Overview

This Flask application receives GitHub webhook events (star/watch), deduplicates them, and sends Discord notifications for first-time user interactions. It supports both SQLite (default) and PostgreSQL databases with encrypted secret storage.

**Key Architecture Pattern**: Database-agnostic design using wrapper classes (`DatabaseWrapper`, `PostgreSQLCursorWrapper`) to abstract SQLite/PostgreSQL differences. All SQL queries must work with both engines.

## Critical Configuration

### Required Environment Variables
Three secrets **MUST** be set or the app exits immediately:
- `ENCRYPTION_KEY`: Fernet key for encrypting webhook secrets
- `ADMIN_PASSWORD_HASH`: Argon2id hash for admin authentication  
- `FLASK_SECRET_KEY`: Session secret (64-char hex)

**Generate all secrets**: Activate venv first, then run `python scripts/generate_required_secrets.py`

### Database Selection Logic
PostgreSQL is used **only if ALL five** env vars are set (`POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`). Missing any? Falls back to SQLite at `GitHub_Events_Limiter/data.db`.

## Code Organization

### Blueprint Architecture
Routes are organized into three blueprints in `routes/`:
- **`web.py`**: Public routes (`/`, `/send`, `/health`, `/stats`)
- **`api.py`**: Protected API routes (`/api/*`) - requires API key or CSRF token
- **`admin.py`**: Admin panel (`/admin/*`) - requires session auth or admin API key

**Initialization Pattern**: Each blueprint exports an `init_*_routes(...)` function that receives dependencies (logger, db handlers, etc.) from `main.py`. The `routes/__init__.py` orchestrates registration via `register_blueprints(app, helpers)`.

### Handler Modules Pattern
Business logic lives in `modules/*Handler.py` classes:
- **`AuthenticationHandler`**: API key hashing (Argon2id), rate limiting, decorators (`@require_api_key_or_csrf`, `@require_admin_auth`)
- **`SecurityHandler`**: Fernet encryption/decryption, HMAC signature verification for GitHub webhooks
- **`GitHubHandler`**: GitHub API calls (fetch repo metadata, verify webhooks)
- **`DiscordHandler`**: Discord webhook verification and embed sending
- **`StatisticsHandler`**: Event tracking, top users analytics, cleanup tasks
- **`DatabaseWrapper`**: SQL abstraction layer for SQLite vs PostgreSQL timestamp/syntax differences

**Import Pattern**: Third-party modules from `.config/` (like `config.py`) are added to `sys.path` before local imports. See `main.py` lines 39-42.

## Virtual Environment Management

### Setup and Activation (MANDATORY for all Python operations)
All Python code execution, testing, and linting MUST be performed within the virtual environment.

**Check if venv exists**:
```powershell
Test-Path ".venv"
```

**If venv doesn't exist, create it**:
```powershell
# Create virtual environment using py launcher
py -m venv .venv

# Activate the virtual environment
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

**If venv exists, activate it**:
```powershell
.venv\Scripts\Activate.ps1
```

**Verification**: After activation, the PowerShell prompt should show `(.venv)` prefix. Verify Python is using the venv:
```powershell
(Get-Command python).Source  # Should point to .venv\Scripts\python.exe
```

**CRITICAL**: Always activate the venv BEFORE running any Python commands (tests, linting, server startup, scripts).

## Database Operations

### Query Conversion
**Never write PostgreSQL-only SQL**. Use `DatabaseWrapper` helpers:

```python
# ❌ Wrong - hardcoded PostgreSQL syntax
query = "INSERT ... ON CONFLICT ... SET created_at = to_timestamp(?)"

# ✅ Correct - database-agnostic
from modules.DatabaseWrapper import DatabaseWrapper
db_wrapper = DatabaseWrapper(db_type)
query = db_wrapper.build_insert_cleanup_task()
```

**Common patterns**:
- Timestamps: Use `db_wrapper.timestamp_placeholder()` (returns `to_timestamp(?)` for PostgreSQL, `?` for SQLite)
- Conflict handling: PostgreSQL uses `ON CONFLICT ... DO UPDATE`, SQLite uses `INSERT OR REPLACE` or `ON CONFLICT ... DO UPDATE`
- The wrapper classes (`PostgreSQLCursorWrapper`, `PostgreSQLConnectionWrapper`) auto-convert `?` to `%s` for PostgreSQL

### Connection Management
Database connections use Flask's `g` object (request-scoped):
```python
db = get_db()  # Returns wrapped connection
cursor = db.cursor()  # Returns dict cursor (compatible with both DBs)
```

Auto-closed after request via `@app.teardown_appcontext`.

## Authentication & Authorization

### Two Authentication Systems
1. **API Keys** (programmatic access): 
   - Hashed with Argon2id, stored in `api_keys` table
   - Permission bitmap system (see `CustomModules.bitmap_handler`)
   - Rate limited per key (see `AuthenticationHandler.enforce_rate_limit`)

2. **Admin Sessions** (web interface):
   - Password verified via `verify_admin_password()`
   - Session-based with CSRF protection
   - Internal routes protected by `X-Internal-Secret` header

### Permission System
Permissions use a bitmap stored as integer. Example from `routes/api.py`:
```python
@check_permission("repositories-add")  # Decorator checks if API key has this permission
def add_repository():
    ...
```

Admin API keys bypass all permissions (see `AuthenticationHandler.verify_api_key_permissions`).

## Testing Workflow

### Complete Testing Protocol (MANDATORY)
**CRITICAL**: A test is only considered PASSED when ALL of the following succeed with ZERO errors, issues, or skips:

### Docker Stack Testing (RECOMMENDED - Fully Automated)
The project includes a comprehensive test suite (`test-all.ps1`) that runs the server and tests in separate containers. This is the **preferred testing method** as it's fully automated and the agent has complete control.

**Architecture**:
- **Server Container**: Runs the Flask application with health checks and auto-created test API key
- **Test Runner Container**: Waits for server health, then runs pytest
- **Automatic Cleanup**: Database and containers cleaned before/after tests
- **Test Environment**: Uses `TEST_API_KEY_PLAINTEXT` from `.env` to auto-create admin API key in database

#### Test All Configurations (Default)
```powershell
.\test-all.ps1
```
**What it does**:
1. Tests SQLite configuration:
   - Cleans up existing containers and SQLite database
   - Creates `.env.docker` with escaped `$$` for Argon2 password hashes
   - Builds server and test-runner containers
   - Starts server container with health checks
   - Server auto-creates admin API key from `TEST_API_KEY_PLAINTEXT` environment variable
   - Waits for server to be healthy (max 120 seconds)
   - Runs pytest in test-runner container (all 64 tests)
   - Reports results and cleans up
2. Tests PostgreSQL configuration (embedded server):
   - Same process as SQLite but uses PostgreSQL
   - PostgreSQL runs inside the server container
3. Reports final summary of all test results

**Exit codes**: Returns 0 if all tests pass, non-zero if any fail.

**Expected Results**: All 64 tests should pass for both configurations (58 in `test_all_endpoints.py`, 6 in `test_authentication.py`).

#### Test Specific Configuration
```powershell
# SQLite only
.\test-all.ps1 -Configuration sqlite

# PostgreSQL only
.\test-all.ps1 -Configuration postgresql
```

#### Advanced Options
```powershell
# Stop at first failure
.\test-all.ps1 -FailFast

# Keep containers running for debugging
.\test-all.ps1 -Configuration sqlite -KeepRunning

# View full container logs after tests
.\test-all.ps1 -ViewLogs

# PostgreSQL with logs and fail-fast
.\test-all.ps1 -Configuration postgresql -ViewLogs -FailFast
```

**For debugging failed tests**:
```powershell
# Run with KeepRunning to inspect
.\test-all.ps1 -Configuration sqlite -KeepRunning

# In another terminal, check server logs
docker-compose -f docker-compose.test.yml logs server

# Or access test results volume
docker run --rm -v github-stars-webhook-limiter_test-results:/data alpine ls -la /data

# Clean up when done
docker-compose -f docker-compose.test.yml down -v
```

### Alternative: Manual Testing (For Local Development)
If you need to test changes without Docker or want to debug interactively:

#### 1. Native Python Server
```powershell
# Terminal 1 (user runs manually):
.venv\Scripts\Activate.ps1
Remove-Item -Path "GitHub_Events_Limiter\data.db" -ErrorAction SilentlyContinue
python main.py

# Terminal 2 (agent can run):
.venv\Scripts\Activate.ps1; cd Tests; python -m pytest . -v
```

#### 2. Docker Debugging (Individual Containers)
```powershell
# SQLite
.\debug_docker.ps1  # User runs in separate terminal
.venv\Scripts\Activate.ps1; cd Tests; python -m pytest . -v  # Agent runs

# PostgreSQL
.\debug_docker_postgresql.ps1  # User runs in separate terminal
.venv\Scripts\Activate.ps1; cd Tests; python -m pytest . -v  # Agent runs
```

**CRITICAL**: When running manual tests, the server MUST be started in a separate terminal and left running until tests complete. The agent cannot reliably start and test in the same terminal session due to tool limitations.

**All test configurations MUST complete successfully** (no errors, no skips, all 64 tests passing). Use the Docker stack method (`test-stack.ps1`) for automated, reliable testing.

## Development Commands

### Linting (MANDATORY for ALL code changes)
**CRITICAL**: These commands MUST ALL succeed before any code change is considered complete. Run them in order:

**PREREQUISITE**: Activate virtual environment before linting:
```powershell
.venv\Scripts\Activate.ps1
```

**Linting commands**:
```powershell
# 1. Format imports
python -m isort .

# 2. Format code
python -m black .

# 3. Check style
python -m flake8 .

# 4. Static analysis (must score ≥10.0)
python -m pylint *.py routes modules --fail-under=10.0
```

**All four must pass with zero errors**. If any fail, fix the issues before proceeding.

**Exclusions**: `pyproject.toml` excludes `Tests/`, `GitHub_Events_Limiter/`, `.venv/` from linters.

### Debugging
- **SQLite**: `.\debug_docker.ps1` (uses `docker-compose.yml`)
- **PostgreSQL**: `.\debug_docker_postgresql.ps1` (embedded PostgreSQL in container)
- Logs stored in `GitHub_Events_Limiter/logs/` (persistent volume)

## Docker Architecture

### Multi-Stage Builds
Two Dockerfiles:
- `Dockerfile`: SQLite version (uses `requirements-sqlite.txt`)
- `Dockerfile.postgresql`: PostgreSQL version (uses `requirements-postgresql.txt`, includes PostgreSQL server)

**Important**: The PostgreSQL Docker image runs its own embedded PostgreSQL server for simplicity. Not exposed outside container.

### Deployment Variants
Three docker-compose files:
- `docker-compose.yml`: SQLite or external PostgreSQL
- `docker-compose.postgresql.yml`: Embedded PostgreSQL
- `docker-compose.external-postgres.yml`: External PostgreSQL server

## Common Patterns

### Encrypted Secret Storage
All webhook secrets encrypted at rest:
```python
# Storing
encrypted = encrypt_secret(plain_secret)  # Returns bytes
db.execute("INSERT INTO repositories (..., secret) VALUES (..., ?)", (encrypted,))

# Retrieving
encrypted = row["secret"]
plain = decrypt_secret(encrypted)  # Returns string
```

### GitHub Webhook Verification
```python
signature = request.headers.get("X-Hub-Signature-256")
payload = request.get_data()
if not verify_github_signature(secret, signature, payload):
    return jsonify({"error": "Invalid signature"}), 401
```

### Discord Notifications
Handled by `DiscordHandler.send_notification()` which uses embeds with repo/user metadata. Includes color-coding: blue (star), green (watch).

## Statistics & Periodic Tasks

### Background Tasks (`periodic_tasks.py`)
Tasks run via `PeriodicTaskManager`:
- **Cleanup old events** (90 days retention)
- **Webhook verification** (tests Discord webhooks monthly)
- **GitHub repo validation** (verifies repo exists quarterly)
- **Log rotation** (weekly, keeps 30 days)

Tasks use `cleanup_tasks` table to track last run time.

### Statistics Tracking
`StatisticsHandler` tracks counts via `statistics` table:
- Total stars/watches received
- Unique users
- API calls, webhook events
- Incremented via `increment_stat("metric_name")`

## Security Best Practices

### Pre-Commit Security Scanning
**Always run Snyk scan** before completing significant code changes:
```powershell
# See .github/instructions/snyk_rules.instructions.md
```

### Secret Validation
The app validates on startup that:
1. All required env vars are set
2. No placeholder values (checks against `config.INVALID_PLACEHOLDERS`)
3. `ADMIN_PASSWORD_HASH` is valid Argon2 format

Exits immediately if validation fails.

### Rate Limiting
API keys have configurable rate limits (requests per hour). Admin keys bypass limits. See `AuthenticationHandler.enforce_rate_limit()`.

## Gotchas & Edge Cases

1. **PostgreSQL `lastrowid`**: PostgreSQL doesn't support `cursor.lastrowid`. The `PostgreSQLCursorWrapper` automatically adds `RETURNING id` to INSERT statements.

2. **Docker env vars**: Argon2 hashes contain `$` which Docker's `--env-file` mishandles. **Always use docker-compose** or escape properly.

3. **Repository ID resilience**: Repos stored by GitHub's internal repo ID (not name) to survive renames. See `GitHubHandler.get_repository_info()`.

4. **Event deduplication**: Keyed on `(github_user_id, repository_id, event_type)` in `user_events` table.

5. **Admin panel secret bypass**: Admin API keys can modify/delete repositories **without knowing webhook secrets** for convenience.

6. **Health check logging**: Requests with `User-Agent: Healthcheck` log at DEBUG level to reduce noise. See `/health` route in `routes/web.py`.

## File Locations

- **Main app**: `main.py` (1200+ lines - initialization, database setup, signal handling)
- **Config**: `.config/config.py` (constants, paths, placeholder lists)
- **Blueprints**: `routes/{web,api,admin}.py`
- **Handlers**: `modules/*Handler.py`
- **Custom libs**: `CustomModules/` (imported from external package)
- **Tests**: `Tests/*.py` (requires running server)
- **Static assets**: `templates/*.html`, `static/*.{css,js}`
- **Scripts**: `scripts/generate_required_secrets.py`, `scripts/bulk_create_keys.py`

## When Modifying Code

**MANDATORY Pre-Completion Checklist:**
1. **Virtual Environment**: Ensure venv exists and is activated (`.venv\Scripts\Activate.ps1`) - create if missing (`py -m venv .venv`)
2. **Linting**: Run ALL four linting commands (`isort`, `black`, `flake8`, `pylint`) - must pass with zero errors
3. **Testing**: Run automated Docker stack tests for BOTH configurations:
   - All configurations: `.\test-all.ps1` - must exit with code 0
   - Or individual: `.\test-all.ps1 -Configuration sqlite` / `.\test-all.ps1 -Configuration postgresql`
4. **Security**: Run Snyk scan for significant code changes (see `.github/instructions/snyk_rules.instructions.md`)

**Code-Specific Guidelines:**
1. **Database queries**: Test with both SQLite AND PostgreSQL
2. **Route changes**: Update OpenAPI spec in `static/openapi.yaml`
3. **Permissions**: Update bitmap definitions if adding new permissions
4. **Secrets**: Never log decrypted secrets (use `<encrypted>` placeholder)
5. **Error handling**: Return proper HTTP status codes matching existing patterns
6. **Logging**: Use appropriate levels (DEBUG for verbose, INFO for key events, ERROR for failures)

