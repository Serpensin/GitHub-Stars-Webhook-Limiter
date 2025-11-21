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

import os
import secrets
import signal
import sqlite3
import sys
import time

import sentry_sdk
from argon2 import PasswordHasher
from argon2 import exceptions as argon2_exceptions
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, g, render_template, request, send_from_directory, session

# PostgreSQL imports (optional - only needed if using PostgreSQL)
try:
    import psycopg
    from psycopg.rows import dict_row as psycopg_dict_row
    from psycopg_pool import ConnectionPool
except ImportError:
    psycopg = None  # type: ignore
    ConnectionPool = None  # type: ignore
    psycopg_dict_row = None  # type: ignore

# Add .config folder to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".config"))

import config  # type: ignore  # config is in .config folder, added to path above

from CustomModules.bitmap_handler import BitmapHandler
from CustomModules.database_handler import SQLiteDatabaseHandler, SyncDatabaseHandler
from CustomModules.log_handler import LogManager
from modules.AuthenticationHandler import AuthenticationHandler
from modules.DiscordHandler import DiscordHandler
from modules.GitHubHandler import GitHubHandler
from modules.SecurityHandler import SecurityHandler
from modules.StatisticsHandler import StatisticsHandler
from periodic_tasks import PeriodicTaskManager

load_dotenv()

# Initialize logging (logs stored in persistent volume)
os.makedirs(config.LOG_FOLDER, exist_ok=True)
log_manager = LogManager(config.LOG_FOLDER, config.APP_NAME, config.LOG_LEVEL)
logger = log_manager.get_logger(__name__)

# Initialize password hasher for API keys and admin auth
ph = PasswordHasher()


# ============================================================================
# Database Connection Wrappers
# ============================================================================


class PostgreSQLCursorWrapper:
    """Wrapper for PostgreSQL cursor that converts SQLite-style queries."""

    def __init__(self, cursor):
        self._cursor = cursor
        self._lastrowid = None

    def execute(self, query, params=None):
        """Execute query with automatic parameter conversion."""
        converted = query.replace("?", "%s")

        # For INSERT statements, add RETURNING id to get lastrowid
        if converted.strip().upper().startswith("INSERT"):
            # Check if RETURNING clause already exists
            if "RETURNING" not in converted.upper():
                # Add RETURNING id before any trailing semicolon
                converted = converted.rstrip().rstrip(";") + " RETURNING id"

            # Execute and fetch the returned ID
            result = (
                self._cursor.execute(converted, params)
                if params
                else self._cursor.execute(converted)
            )

            # Fetch the returned ID
            row = self._cursor.fetchone()
            if row:
                self._lastrowid = row[0] if isinstance(row, tuple) else row.get("id")

            return result

        return (
            self._cursor.execute(converted, params) if params else self._cursor.execute(converted)
        )

    def fetchone(self):
        """Fetch one row."""
        return self._cursor.fetchone()

    def fetchall(self):
        """Fetch all rows."""
        return self._cursor.fetchall()

    @property
    def rowcount(self):
        """Return row count."""
        return self._cursor.rowcount

    @property
    def description(self):
        """Return cursor description."""
        return self._cursor.description

    @property
    def lastrowid(self):
        """Return the last inserted row ID."""
        return self._lastrowid

    def close(self):
        """Close cursor."""
        return self._cursor.close()


class PostgreSQLConnectionWrapper:
    """Wrapper that automatically converts SQLite queries to PostgreSQL syntax."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, query, params=None):
        """Execute with automatic query conversion."""
        converted = query.replace("?", "%s")
        return self._conn.execute(converted, params) if params else self._conn.execute(converted)

    def cursor(self):
        """Return wrapped cursor."""
        # Ensure cursor uses dict row factory for SQLite compatibility
        base_cursor = self._conn.cursor(row_factory=psycopg_dict_row)
        return PostgreSQLCursorWrapper(base_cursor)

    def commit(self):
        """Commit transaction."""
        return self._conn.commit()

    def rollback(self):
        """Rollback transaction."""
        return self._conn.rollback()

    def close(self):
        """Close connection."""
        return self._conn.close()

    def get_connection(self):
        """Return the underlying connection for pool management."""
        return self._conn


# ============================================================================
# Validation and Configuration
# ============================================================================


def validate_argon2_hash(hash_string: str) -> bool:
    try:
        ph.verify(hash_string, "dummy_password")
    except argon2_exceptions.VerifyMismatchError:
        return True  # valid hash, just wrong password
    except argon2_exceptions.InvalidHashError:
        return False  # invalid format
    except argon2_exceptions.VerificationError:
        return False  # corrupted or invalid internal structure
    return True


# Check for required environment variables and validate them
REQUIRED_ENV_VARS = ["ENCRYPTION_KEY", "ADMIN_PASSWORD_HASH", "FLASK_SECRET_KEY"]
missing_vars = []
invalid_vars = []

for var in REQUIRED_ENV_VARS:
    value = os.environ.get(var)

    if not value:
        missing_vars.append(var)
        continue

    # Check if value is a placeholder
    if value in config.INVALID_PLACEHOLDERS.get(var, []):
        invalid_vars.append((var, "placeholder value detected"))
        continue

    # Special validation for ADMIN_PASSWORD_HASH
    if var == "ADMIN_PASSWORD_HASH" and not validate_argon2_hash(value):
        invalid_vars.append((var, "not a valid Argon2 hash"))

if missing_vars or invalid_vars:
    logger.critical("=" * 70)
    logger.critical("FATAL ERROR: Invalid environment configuration!")
    logger.critical("=" * 70)

    if missing_vars:
        logger.critical("Missing variables:")
        for var in missing_vars:
            logger.critical(f"  - {var}")

    if invalid_vars:
        logger.critical("Invalid variables:")
        for var, reason in invalid_vars:
            logger.critical(f"  - {var}: {reason}")

    logger.critical("")
    logger.critical("The application cannot start with invalid configuration.")
    logger.critical(
        "Run 'python .\\scripts\\generate_required_secrets.py' to generate valid secrets."
    )
    logger.critical("=" * 70)

    print("\nFATAL ERROR: Invalid environment configuration!")
    print("=" * 70)

    if missing_vars:
        print("\nMissing variables:")
        for var in missing_vars:
            print(f"  - {var}")

    if invalid_vars:
        print("\nInvalid variables:")
        for var, reason in invalid_vars:
            print(f"  - {var}: {reason}")

    print("\n" + "=" * 70)
    print("Run 'python .\\scripts\\generate_required_secrets.py' to generate valid secrets.")
    print("Then add the generated values to your .env file or environment.")
    print("=" * 70 + "\n")
    sys.exit(1)

# Initialize encryption key
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
logger.info("Encryption key loaded and validated")

# At this point ENCRYPTION_KEY is guaranteed to be non-None due to validation above
assert ENCRYPTION_KEY is not None, "ENCRYPTION_KEY should have been validated"
cipher_suite = Fernet(
    ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY
)

# CSRF protection will use session-based tokens
# No global secret needed - each session gets its own token
logger.info("CSRF protection enabled via session tokens")

# Initialize admin password hash
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
logger.info("Admin password hash loaded from environment")

# At this point ADMIN_PASSWORD_HASH is guaranteed to be non-None due to validation above
assert ADMIN_PASSWORD_HASH is not None, "ADMIN_PASSWORD_HASH should have been validated"

# Initialize GitHub token for API access
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
if GITHUB_TOKEN:
    logger.info("GitHub token loaded from environment")
else:
    logger.warning("GitHub token not configured - repository data fetching may fail")

# Initialize Sentry SDK for error monitoring and performance tracing
sentry_dsn = os.environ.get("SENTRY_DSN")
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        send_default_pii=True,
        traces_sample_rate=1.0,
        profile_session_sample_rate=1.0,
        profile_lifecycle="trace",
        environment="Production",
        release=f"{config.APP_NAME}@{config.APP_VERSION}",
    )
    logger.info(f"Sentry SDK initialized for {config.APP_NAME}@{config.APP_VERSION}")
else:
    logger.info("Sentry SDK disabled (no DSN provided)")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
logger.info("Flask secret key loaded from environment")

# Generate internal server secret for internal-only routes (login/logout)
# This prevents external access to admin login/logout endpoints
# Only the admin panel HTML page will have access to this secret
INTERNAL_SERVER_SECRET = secrets.token_urlsafe(32)
logger.info("Internal server secret generated for admin panel routes")

logger.info(f"Flask application '{config.APP_NAME}' v{config.APP_VERSION} starting up")

# Track server start time to invalidate all previous admin sessions
SERVER_START_TIME = int(time.time())
logger.info(f"Server start time: {SERVER_START_TIME}")

os.makedirs(config.APP_NAME, exist_ok=True)

# ============================================================================
# Database Initialization
# ============================================================================


def initialize_database():
    """
    Initialize database handler based on environment variables.

    Returns:
        tuple: (db_handler, db_type, db_info)
            - db_handler: Either SQLiteDatabaseHandler or SyncDatabaseHandler
            - db_type: "sqlite" or "postgresql"
            - db_info: Database path (SQLite) or connection string (PostgreSQL)
    """
    # Check for PostgreSQL environment variables
    postgres_host = os.environ.get("POSTGRES_HOST")
    postgres_port = os.environ.get("POSTGRES_PORT", "5432")
    postgres_db = os.environ.get("POSTGRES_DB")
    postgres_user = os.environ.get("POSTGRES_USER")
    postgres_password = os.environ.get("POSTGRES_PASSWORD")

    # Use PostgreSQL if all required variables are set
    if all([postgres_host, postgres_db, postgres_user, postgres_password]):
        db_type = "postgresql"
        connection_string = (
            f"postgresql://{postgres_user}:{postgres_password}@"
            f"{postgres_host}:{postgres_port}/{postgres_db}"
        )
        logger.info(f"Using PostgreSQL database: {postgres_host}:{postgres_port}/{postgres_db}")
        db_handler = SyncDatabaseHandler.create(connection_string, logger)
        db_info = connection_string
    else:
        # Default to SQLite
        db_type = "sqlite"
        db_path = os.path.join(config.APP_NAME, "data.db")
        logger.info(f"Using SQLite database at {os.path.abspath(db_path)}")
        db_handler = SQLiteDatabaseHandler(db_path, logger)
        db_info = db_path

    return db_handler, db_type, db_info


# Initialize database
db_handler, db_type, db_info = initialize_database()


def convert_query_for_db(query: str) -> str:
    """
    Convert SQLite query syntax to PostgreSQL if needed.

    Args:
        query: SQL query string with ? placeholders (SQLite style)

    Returns:
        Converted query string for the current database type
    """
    if db_type == "postgresql":
        # Convert ? placeholders to %s for PostgreSQL
        return query.replace("?", "%s")
    return query


# Initialize database schema
# With preload_app=True in Gunicorn, this runs once in the master process before forking workers
try:
    logger.info("Setting up database schema")

    # Helper function to create table with PostgreSQL race condition handling
    def create_table_safe(query: str, table_name: str):
        """Create table with error handling for PostgreSQL race conditions"""
        try:
            db_handler.execute(query, commit=True, fetch=False)
            logger.debug(f"{table_name} table created/verified")
        except Exception as e:
            error_msg = str(e).lower()
            # Ignore "already exists" errors (can happen with multiple workers)
            if "already exists" in error_msg or "duplicate" in error_msg:
                logger.debug(f"{table_name} table already exists (race condition)")
            else:
                raise

    # Define common SQL fragments for table creation
    if db_type == "postgresql":
        pk_def = "SERIAL PRIMARY KEY,"
    else:
        pk_def = "INTEGER PRIMARY KEY AUTOINCREMENT,"

    # Table for tracking starred/watched repos
    user_events_query = f"""
        CREATE TABLE IF NOT EXISTS user_events (
            id {pk_def}
            github_user_id INTEGER NOT NULL,
            repository_id INTEGER NOT NULL,
            event_type VARCHAR(64) NOT NULL,
            UNIQUE(github_user_id, repository_id, event_type)
        )
        """
    create_table_safe(user_events_query, "user_events")

    # Table for repository configurations
    repositories_query = f"""
        CREATE TABLE IF NOT EXISTS repositories (
            id {pk_def}
            repo_id INTEGER NOT NULL UNIQUE,
            repo_full_name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            secret_encrypted TEXT NOT NULL,
            discord_webhook_url TEXT NOT NULL,
            enabled_events TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_event_received TIMESTAMP,
            last_repo_checked TIMESTAMP,
            last_webhook_checked TIMESTAMP
        )
        """
    create_table_safe(repositories_query, "repositories")
    logger.debug("repositories table created/verified")

    # Table for API keys (permissions as bitmap integer)
    api_keys_query = f"""
        CREATE TABLE IF NOT EXISTS api_keys (
            id {pk_def}
            key_hash VARCHAR(64) NOT NULL UNIQUE,
            name VARCHAR(512) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            permissions INTEGER DEFAULT 0 CHECK (is_admin_key = 1 OR permissions > 0),
            rate_limit INTEGER DEFAULT 100,
            is_admin_key INTEGER DEFAULT 0
        )
        """
    create_table_safe(api_keys_query, "api_keys")

    # Table for API rate limiting tracking
    # Stores only: key_id, first_request_time, request_count
    create_table_safe(
        """
        CREATE TABLE IF NOT EXISTS api_rate_limit_tracking (
            api_key_id INTEGER PRIMARY KEY,
            first_request_time TIMESTAMP NOT NULL,
            request_count INTEGER DEFAULT 1,
            FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
        )
        """,
        "api_rate_limit_tracking",
    )

    # Table for tracking when periodic cleanup tasks last ran
    create_table_safe(
        """
        CREATE TABLE IF NOT EXISTS cleanup_tasks (
            task_name VARCHAR(255) PRIMARY KEY,
            last_run TIMESTAMP NOT NULL
        )
        """,
        "cleanup_tasks",
    )

    # Table for storing cumulative statistics
    # Use UNLOGGED for PostgreSQL to skip WAL writes (statistics are not critical)
    unlogged = "UNLOGGED " if db_type == "postgresql" else ""
    statistics_query = f"""
        CREATE {unlogged}TABLE IF NOT EXISTS statistics (
            id {pk_def}
            stat_name VARCHAR(255) NOT NULL UNIQUE,
            stat_value INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    create_table_safe(statistics_query, "statistics")

    # Table for per-user event statistics
    create_table_safe(
        """
        CREATE TABLE IF NOT EXISTS user_statistics (
            github_user_id INTEGER PRIMARY KEY,
            github_username TEXT,
            valid_events INTEGER DEFAULT 0,
            invalid_events INTEGER DEFAULT 0,
            last_event_timestamp TIMESTAMP
        )
        """,
        "user_statistics",
    )
    logger.debug("user_statistics table created/verified")

    # ========================================================================
    # Create performance indexes
    # ========================================================================
    logger.info("Creating database indexes for performance")

    # Index for key_hash is automatically created by UNIQUE constraint - no need for explicit index

    # Index for filtering active/inactive keys
    create_table_safe(
        "CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active)",
        "idx_api_keys_active",
    )

    # Index for user_events lookups (supports UNIQUE constraint)
    create_table_safe(
        """CREATE INDEX IF NOT EXISTS idx_user_events_lookup
           ON user_events(github_user_id, repository_id, event_type)""",
        "idx_user_events_lookup",
    )

    # Index for repository lookups
    create_table_safe(
        "CREATE INDEX IF NOT EXISTS idx_repositories_repo_id ON repositories(repo_id)",
        "idx_repositories_repo_id",
    )

    # Index for stat_name is automatically created by UNIQUE constraint - no need for explicit index

    logger.info("Database initialization completed successfully")

    # ========================================================================
    # Auto-create test API key if environment variable is set
    # ========================================================================
    test_api_key = os.environ.get("TEST_API_KEY_PLAINTEXT")
    test_api_key_name = os.environ.get("TEST_API_KEY_NAME", "Auto-Created Test Key")

    if test_api_key:
        import hashlib

        logger.info("TEST_API_KEY_PLAINTEXT detected - checking for existing test key")

        # Hash the API key (same method as AuthenticationHandler.hash_api_key)
        key_hash = hashlib.sha256(test_api_key.encode("utf-8")).hexdigest()

        # Check if key already exists using db_handler
        try:
            result = db_handler.execute(
                convert_query_for_db("SELECT id, name FROM api_keys WHERE key_hash = ?"),
                (key_hash,),
                commit=False,
                fetch=True,
            )

            if result and len(result) > 0:  # type: ignore
                # Result is a list of rows (dict or tuple depending on DB type)
                first_row = result[0]  # type: ignore
                existing_id = (
                    first_row["id"]
                    if hasattr(first_row, "__getitem__") and isinstance(first_row, dict)
                    else first_row[0]
                )  # type: ignore
                logger.info(f"Test API key already exists in database (ID: {existing_id})")
                logger.info("  Skipping creation - using existing key")
            else:
                # Create new test API key with all permissions
                logger.info("Creating test API key with full admin permissions")

                # Calculate max permissions (all bits set)
                max_permissions = (1 << len(config.PERMISSIONS)) - 1

                # Use database-specific INSERT ... ON CONFLICT
                # for SQLite/PostgreSQL compatibility
                if db_type == "postgresql":
                    insert_query = """INSERT INTO api_keys
                                      (key_hash, name, permissions, rate_limit,
                                       is_admin_key, is_active)
                                      VALUES (%s, %s, %s, %s, %s, %s)
                                      ON CONFLICT (key_hash) DO NOTHING"""
                else:  # SQLite
                    insert_query = """INSERT OR IGNORE INTO api_keys
                                      (key_hash, name, permissions, rate_limit,
                                       is_admin_key, is_active)
                                      VALUES (?, ?, ?, ?, ?, ?)"""

                db_handler.execute(
                    insert_query,
                    (key_hash, test_api_key_name, max_permissions, 1000, 1, 1),
                    commit=True,
                    fetch=False,
                )

                # Check if it was actually inserted or already existed
                result_check = db_handler.execute(
                    convert_query_for_db("SELECT id FROM api_keys WHERE key_hash = ?"),
                    (key_hash,),
                    commit=False,
                    fetch=True,
                )

                if result_check and len(result_check) > 0:  # type: ignore
                    logger.info(f"Test API key ready: '{test_api_key_name}'")
                    logger.info("  Permissions: -1 (Admin)")
                    logger.info("  Rate Limit: 1000")
                    logger.info(f"  Key Hash: {key_hash[:16]}...")
        except Exception as e:
            logger.error(f"Failed to create/check test API key: {e}")

except Exception as e:
    logger.critical(f"Database initialization failed: {e}")
    sys.exit(f"Database error: {e}")

# ============================================================================
# Signal Handler for Graceful Shutdown
# ============================================================================


class SignalHandler:
    """
    Handles shutdown signals (SIGINT, SIGTERM) to gracefully stop the application.
    Ensures database connections are closed and periodic tasks are stopped.
    """

    def __init__(self):
        self.shutdown_initiated = False

        # Register signal handlers (only works in main thread)
        try:
            signal.signal(signal.SIGINT, self._shutdown)
            signal.signal(signal.SIGTERM, self._shutdown)
            logger.info("Signal handlers registered (SIGINT, SIGTERM)")
        except ValueError:
            # Not in main thread (e.g., when running under Gunicorn)
            logger.debug("Signal handlers not registered (not in main thread)")

    def _shutdown(self, signum, frame):
        """
        Handle shutdown signals gracefully.

        Args:
            signum: Signal number
            frame: Current stack frame
        """
        if self.shutdown_initiated:
            logger.warning("Shutdown already in progress, ignoring duplicate signal")
            return

        self.shutdown_initiated = True
        signal_name = signal.Signals(signum).name
        logger.info(f"Received {signal_name}, initiating graceful shutdown...")

        try:
            # Close db_handler connection first
            db_handler.close()
            logger.info("Database connections closed")

            # Perform WAL checkpoint only for SQLite
            if db_type == "sqlite":
                logger.info("Running database WAL checkpoint and truncate...")
                conn = sqlite3.connect(db_info)
                try:
                    # TRUNCATE mode: checkpoint and remove WAL/SHM files
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                    logger.info("WAL checkpoint and truncate completed")
                finally:
                    conn.close()

            # Note: Periodic tasks run in daemon threads and will stop automatically
            logger.info("Periodic tasks will stop automatically (daemon threads)")

            logger.info("Graceful shutdown completed")

        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        finally:
            # Exit the application
            sys.exit(0)


# Initialize signal handler
signal_handler = SignalHandler()


# ============================================================================
# Database Connection and Request Lifecycle
# ============================================================================

# PostgreSQL connection pool (global, shared across workers)
_postgres_pool = None

if db_type == "postgresql":
    if ConnectionPool is None or psycopg_dict_row is None:
        logger.error(
            "PostgreSQL database type selected but psycopg_pool not installed. "
            "Install with: pip install psycopg[pool]"
        )
        sys.exit("Missing PostgreSQL dependencies")

    try:
        postgres_host = os.environ.get("POSTGRES_HOST")
        postgres_port = os.environ.get("POSTGRES_PORT", "5432")
        postgres_db = os.environ.get("POSTGRES_DB")
        postgres_user = os.environ.get("POSTGRES_USER")
        postgres_password = os.environ.get("POSTGRES_PASSWORD")

        conninfo = (
            f"host={postgres_host} "
            f"port={postgres_port} "
            f"user={postgres_user} "
            f"password={postgres_password} "
            f"dbname={postgres_db}"
        )

        # Create connection pool with optimized settings
        # min_size: Minimum connections kept alive
        # max_size: Maximum connections per worker (4 workers * 25 = 100 total max)
        # configure: Set row_factory for all connections from pool
        _postgres_pool = ConnectionPool(
            conninfo=conninfo,
            min_size=2,  # Keep 2 connections warm per worker
            max_size=25,  # Max 25 connections per worker
            timeout=30.0,  # Wait up to 30s for a connection
            kwargs={"row_factory": psycopg_dict_row},  # All connections use dict rows
        )
        logger.info("PostgreSQL connection pool initialized (min=2, max=25 per worker)")
    except Exception as e:
        logger.error(f"Failed to create PostgreSQL connection pool: {e}")
        sys.exit(f"PostgreSQL connection pool error: {e}")


def _create_sqlite_connection():
    """
    Create and configure a SQLite connection.

    Returns:
        sqlite3.Connection: Configured SQLite connection
    """
    conn = sqlite3.connect(
        db_info,  # This is the SQLite db_path
        timeout=10.0,  # Wait up to 10 seconds for locks
        check_same_thread=False,  # Allow connection to be used across threads with gunicorn
    )
    conn.row_factory = sqlite3.Row

    # Set optimized PRAGMA settings
    # Run 2: Aggressive WAL settings with larger cache and checkpoint interval
    try:
        conn.execute("PRAGMA journal_mode=WAL")  # Enable Write-Ahead Logging
        conn.execute("PRAGMA synchronous=OFF")  # Maximum performance (some risk of corruption if power failure)
        conn.execute("PRAGMA cache_size=-64000")  # 64MB cache (2x baseline)
        conn.execute("PRAGMA temp_store=MEMORY")  # Store temp tables in memory
        conn.execute("PRAGMA busy_timeout=10000")  # Wait up to 10s for locks
        conn.execute("PRAGMA wal_autocheckpoint=10000")  # Larger checkpoint interval for batch writes
    except sqlite3.Error as e:
        logger.error(f"Error setting PRAGMA settings: {e}")

    return conn


def _create_postgresql_connection():
    """
    Create a PostgreSQL connection from pool or direct connection.

    Returns:
        PostgreSQLConnectionWrapper: Wrapped PostgreSQL connection
    """
    # Try to use connection pool first
    if _postgres_pool:
        base_conn = _postgres_pool.getconn()
        # Store pool reference to return connection later
        g.using_pool = True  # pylint: disable=assigning-non-slot
    else:
        # Fallback to direct connection if pool not available
        postgres_host = os.environ.get("POSTGRES_HOST")
        postgres_port = os.environ.get("POSTGRES_PORT", "5432")
        postgres_db = os.environ.get("POSTGRES_DB")
        postgres_user = os.environ.get("POSTGRES_USER")
        postgres_password = os.environ.get("POSTGRES_PASSWORD")

        conninfo = (
            f"host={postgres_host} "
            f"port={postgres_port} "
            f"user={postgres_user} "
            f"password={postgres_password} "
            f"dbname={postgres_db}"
        )

        base_conn = psycopg.connect(conninfo, row_factory=psycopg_dict_row)  # type: ignore
        g.using_pool = False  # pylint: disable=assigning-non-slot

    return PostgreSQLConnectionWrapper(base_conn)


def get_db():
    """
    Retrieves a database connection for the current Flask application context.
    Reuses connection for the entire request lifecycle.
    Connection is automatically committed and closed at request end.

    Note: For PostgreSQL, we wrap the db_handler to provide a cursor-compatible interface.
    For SQLite, we create a direct connection for Flask's request context.

    Returns:
        Connection object (sqlite3.Connection or wrapper for PostgreSQL)
    """
    if "db" not in g:
        if db_type == "sqlite":
            g.db = _create_sqlite_connection()
        else:
            g.db = _create_postgresql_connection()

    return g.db


@app.teardown_appcontext
def close_db(exception=None):  # pylint: disable=unused-argument
    """
    Commits and closes the database connection at the end of the Flask application context.
    For PostgreSQL with pooling, returns the connection to the pool.
    All changes made during the request are committed here unless there was an exception.
    """
    db = g.pop("db", None)
    using_pool = g.pop("using_pool", False)

    if db is not None:
        try:
            if exception is None:
                # Only commit if no exception occurred
                db.commit()
                logger.debug("Database changes committed")
        except Exception as e:  # pylint: disable=broad-except
            logger.error(f"Error committing database changes: {e}")
            db.rollback()
        finally:
            # For PostgreSQL with pool, return connection to pool
            if using_pool and _postgres_pool:
                # Get the underlying connection from wrapper
                if hasattr(db, "get_connection"):
                    _postgres_pool.putconn(db.get_connection())
                    logger.debug("PostgreSQL connection returned to pool")
                else:
                    db.close()
                    logger.debug("Database connection closed")
            else:
                db.close()
                logger.debug("Database connection closed")
    if exception:
        logger.error(f"App context teardown with exception: {exception}")


# ============================================================================
# Permissions Bitmap Setup
# ============================================================================

# Use centralized permission configuration from config.py
PERMISSION_KEYS = config.PERMISSION_KEYS
bitmap_handler = BitmapHandler(PERMISSION_KEYS, logger)

# ============================================================================
# Initialize Security and Authentication Handlers
# ============================================================================

# Initialize security handler for encryption and signature verification
security_handler = SecurityHandler(cipher_suite, logger)

# Initialize authentication handler for API keys and admin auth
auth_handler = AuthenticationHandler(
    password_hasher=ph,
    admin_password_hash=ADMIN_PASSWORD_HASH,
    get_db_func=get_db,
    bitmap_handler=bitmap_handler,
    server_start_time=SERVER_START_TIME,
    db_type=db_type,
    logger=logger,
)

# Initialize statistics handler for metrics tracking
stats_handler = StatisticsHandler(
    get_db_func=get_db,
    db_type=db_type,
    logger=logger,
)

# Initialize Discord handler for webhook notifications
discord_handler = DiscordHandler(logger=logger)

# Initialize GitHub handler for repository operations
github_handler = GitHubHandler(logger=logger, token=GITHUB_TOKEN)

logger.info("Security and authentication handlers initialized")

# Initialize periodic task manager but don't start it yet
# It will be started by Gunicorn's post_fork hook (only in one worker)
# or by the if __name__ == "__main__" block for direct execution
task_manager = PeriodicTaskManager(
    db_handler=db_handler,
    log_manager=log_manager,
    discord_handler=discord_handler,
    github_handler=github_handler,
    send_discord_notification=discord_handler.send_notification,
    db_info=db_info,
    db_type=db_type,
)
logger.info("Periodic task manager initialized (not started yet)")


# ============================================================================
# Database Helper Functions
# ============================================================================


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
            convert_query_for_db(
                "SELECT 1 FROM user_events WHERE github_user_id = ? "
                "AND repository_id = ? AND event_type = ? LIMIT 1"
            ),  # type: ignore
            (github_user_id, repository_id, event_type),
        )
        result = cursor.fetchone() is not None
        logger.debug(
            "User %s has %s triggered %s on repo %s",
            github_user_id,
            "already" if result else "not",
            event_type,
            repository_id,
        )
        return result
    except Exception as e:
        logger.error(f"Database error checking user event: {e}")
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
        query = convert_query_for_db(
            "INSERT OR IGNORE INTO user_events "
            "(github_user_id, repository_id, event_type) VALUES (?, ?, ?)"
        )
        # PostgreSQL doesn't support INSERT OR IGNORE, use ON CONFLICT instead
        if db_type == "postgresql":
            query = (
                "INSERT INTO user_events "
                "(github_user_id, repository_id, event_type) VALUES (%s, %s, %s) "
                "ON CONFLICT (github_user_id, repository_id, event_type) DO NOTHING"
            )
        db.execute(query, (github_user_id, repository_id, event_type))  # type: ignore
        logger.info(f"Recorded {event_type} event: user {github_user_id} on repo {repository_id}")
    except Exception as e:
        logger.error(f"Database error adding user event: {e}")


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
        query = convert_query_for_db("SELECT * FROM repositories WHERE repo_id = ? LIMIT 1")
        cursor = db.execute(query, (repo_id,))  # type: ignore
        row = cursor.fetchone()
        if row:
            logger.debug(f"Retrieved repository config for repo_id {repo_id}")
            return dict(row)
        logger.debug(f"Repository not found: repo_id {repo_id}")
        return None
    except sqlite3.Error as e:
        logger.error(f"Database error getting repository: {e}")
        return None


# ============================================================================
# Register Route Blueprints
# ============================================================================

from routes import register_blueprints

# Prepare helper functions and objects for routes
route_helpers = {
    "logger": logger,
    "get_db": get_db,
    "db_type": db_type,
    "get_repository_by_id": get_repository_by_id,
    "decrypt_secret": security_handler.decrypt_secret,
    "verify_github_signature": security_handler.verify_github_signature,
    "has_user_triggered_event_before": has_user_triggered_event_before,
    "discord_handler": discord_handler,
    "github_handler": github_handler,
    "add_user_event": add_user_event,
    "require_api_key_or_csrf": auth_handler.require_api_key_or_csrf,
    "encrypt_secret": security_handler.encrypt_secret,
    "verify_secret": security_handler.verify_secret,
    "require_admin_auth": auth_handler.require_admin_auth,
    "verify_admin_password": auth_handler.verify_admin_password,
    "hash_api_key": auth_handler.hash_api_key,
    "bitmap_handler": bitmap_handler,
    "increment_stat": stats_handler.increment_stat,
    "get_stat": stats_handler.get_stat,
    "get_all_stats": stats_handler.get_all_stats,
    "get_top_users": stats_handler.get_top_users,
    "internal_server_secret": INTERNAL_SERVER_SECRET,
}

# Register all route blueprints (web, api, admin)
register_blueprints(app, route_helpers)
logger.info("Route blueprints registered successfully")


# ============================================================================
# Request Handlers
# ============================================================================


@app.before_request
def validate_admin_session():
    """
    Validate admin sessions before processing any request.
    This ensures sessions created before server startup are immediately invalidated,
    even if they have a valid signature (Flask uses client-side signed cookies).
    """
    # Only check if there's an admin session
    if session.get("admin_authenticated"):
        admin_login_time = session.get("admin_login_time", 0)

        # Invalidate sessions created before server startup
        if admin_login_time < SERVER_START_TIME:
            logger.warning(
                (
                    "Invalidating admin session created before server startup "
                    "(login_time: %s, server_start: %s) from %s"
                ),
                admin_login_time,
                SERVER_START_TIME,
                request.remote_addr,
            )
            session.pop("admin_authenticated", None)
            session.pop("admin_login_time", None)
            session.modified = True


# Security: Add security headers to all responses
@app.after_request
def add_security_headers(response):
    """Add security headers to all HTTP responses."""
    # Content Security Policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Enable XSS protection
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # HSTS (Strict Transport Security)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Referrer Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Permissions Policy
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


# ============================================================================
# Custom Error Handlers
# ============================================================================


@app.errorhandler(400)
def bad_request(e):
    """Handle 400 Bad Request errors."""
    return render_template("errors/400.html"), 400


@app.errorhandler(401)
def unauthorized(e):
    """Handle 401 Unauthorized errors."""
    return render_template("errors/401.html"), 401


@app.errorhandler(403)
def forbidden(e):
    """Handle 403 Forbidden errors."""
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def not_found(e):
    """Handle 404 Not Found errors."""
    return render_template("errors/404.html"), 404


@app.errorhandler(405)
def method_not_allowed(e):
    """Handle 405 Method Not Allowed errors."""
    return render_template("errors/405.html"), 405


@app.errorhandler(429)
def too_many_requests(e):
    """Handle 429 Too Many Requests errors."""
    return render_template("errors/429.html"), 429


@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 Internal Server Error."""
    logger.error(f"Internal Server Error: {str(e)}", exc_info=True)
    return render_template("errors/500.html"), 500


@app.errorhandler(502)
def bad_gateway(e):
    """Handle 502 Bad Gateway errors."""
    return render_template("errors/502.html"), 502


@app.errorhandler(503)
def service_unavailable(e):
    """Handle 503 Service Unavailable errors."""
    return render_template("errors/503.html"), 503


@app.errorhandler(Exception)
def handle_unexpected_error(e):
    """Catch-all handler for unexpected errors."""
    logger.error(f"Unexpected error: {str(e)}", exc_info=True)
    return render_template("errors/500.html"), 500


# ============================================================================
# Global Favicon Route
# ============================================================================


@app.route("/favicon.ico")
@app.route("/favicon.svg")
def favicon():
    """
    Serves the favicon globally for all pages.
    This centralizes favicon handling - browsers will automatically request this.
    Supports both /favicon.ico (default browser request) and /favicon.svg.
    """
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.svg",
        mimetype="image/svg+xml",
    )


# ============================================================================
# Application Entry Point
# ============================================================================
# Application Entry Point
# ============================================================================


if __name__ == "__main__":
    task_manager.start_all_tasks()
    logger.info("Periodic tasks started (direct execution mode)")

    logger.info(f"Starting {config.APP_NAME} v{config.APP_VERSION} on port 5000")

    debug_mode = os.environ.get("FLASK_DEBUG") == "1"

    if debug_mode:
        ignore_dir = os.path.abspath(config.APP_NAME)

        def list_files_recursive(directory: str):
            base = os.path.abspath(directory)
            for root, _dirs, files in os.walk(base):
                if os.path.abspath(root).startswith(ignore_dir):
                    continue

                for f in files:
                    yield os.path.join(root, f)

        extra_files = list(list_files_recursive("."))
    else:
        extra_files = None

    app.run(host="0.0.0.0", port=5000, debug=debug_mode, extra_files=extra_files)
