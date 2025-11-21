"""
Gunicorn configuration file for GitHub Events Limiter.

This configuration ensures periodic tasks run in only one worker process
to prevent duplicate task execution and database conflicts.
"""

import os
import sqlite3
import sys
from datetime import datetime

# Add parent directory to path FIRST before any other imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

# Monkey patch gevent BEFORE importing anything else that might use SSL/sockets
try:
    import gevent_patch  # This must be first to avoid monkey patch warnings
except ImportError:
    pass  # gevent not available (running in dev mode)

import fcntl
import logging
import tempfile

# Add .config directory (current directory) to path for config import
config_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, config_dir)

# Import central configuration (renamed to avoid conflict with Gunicorn's 'config' variable)
import config as app_config

# Import our custom LogHandler to integrate Gunicorn logs
from CustomModules.database_handler import SQLiteDatabaseHandler
from CustomModules.log_handler import LogManager

# Initialize LogManager for Gunicorn
os.makedirs(app_config.LOG_FOLDER, exist_ok=True)
log_manager = LogManager(app_config.LOG_FOLDER, app_config.APP_NAME, app_config.LOG_LEVEL)


# Custom logger class that uses our LogHandler
class GunicornLogger:
    """Custom Gunicorn logger that integrates with our LogHandler."""

    def __init__(self, cfg):
        self.cfg = cfg
        # Use clearer logger names - "gunicorn" instead of "gunicorn.error"
        self.error_logger = log_manager.get_logger("gunicorn")
        self.access_logger = log_manager.get_logger("gunicorn.access")

        # Set log levels using getLevelNamesMapping() instead of deprecated getLevelName()
        level_name = cfg.loglevel.upper()
        level = logging.getLevelNamesMapping().get(level_name, logging.INFO)
        self.error_logger.setLevel(level)
        self.access_logger.setLevel(level)

    def critical(self, msg, *args, **kwargs):
        self.error_logger.critical(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.error_logger.error(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.error_logger.warning(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self.error_logger.info(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self.error_logger.debug(msg, *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        self.error_logger.exception(msg, *args, **kwargs)

    def log(self, lvl, msg, *args, **kwargs):
        self.error_logger.log(lvl, msg, *args, **kwargs)

    def access(self, resp, _req, environ, _request_time):
        """Log access requests using our custom access logger."""
        user_agent = environ.get("HTTP_USER_AGENT", "-")

        # Use DEBUG level for healthcheck requests to reduce noise
        log_level = logging.DEBUG if user_agent == "Healthcheck" else logging.INFO

        # Format: IP - - [time] "request" status size "referrer" "user-agent"
        self.access_logger.log(
            log_level,
            '%s - - [%s] "%s %s %s" %s %s "%s" "%s"',
            environ.get("REMOTE_ADDR", "-"),
            self.now(),
            environ.get("REQUEST_METHOD", "-"),
            environ.get("PATH_INFO", "-"),
            environ.get("SERVER_PROTOCOL", "-"),
            resp.status.split()[0],
            getattr(resp, "sent", "-"),
            environ.get("HTTP_REFERER", "-"),
            user_agent,
        )

    def now(self):
        """Get current time in logging format."""
        return datetime.now().strftime("%d/%b/%Y:%H:%M:%S %z")

    def reopen_files(self):
        """Reopen log files (no-op for our LogHandler)."""
        pass

    def close_on_exec(self):
        """Close log files on exec (no-op for our LogHandler)."""
        pass


# Server socket
bind = f"{app_config.SERVER_HOST}:{app_config.SERVER_PORT}"
backlog = app_config.GUNICORN_BACKLOG

# Worker processes
workers = app_config.GUNICORN_WORKERS
worker_class = app_config.GUNICORN_WORKER_CLASS
worker_connections = app_config.GUNICORN_WORKER_CONNECTIONS
max_requests = app_config.GUNICORN_MAX_REQUESTS
max_requests_jitter = app_config.GUNICORN_MAX_REQUESTS_JITTER
timeout = app_config.GUNICORN_TIMEOUT
keepalive = app_config.GUNICORN_KEEPALIVE

# Preload application before forking workers
# This ensures database schema initialization happens only once in the master process
preload_app = True

# Logging
logger_class = GunicornLogger  # Use our custom logger class
loglevel = app_config.LOG_LEVEL.lower()
accesslog = None  # Disable default access log (we handle it in custom logger)
errorlog = None  # Disable default error log (we handle it in custom logger)

# Process naming
proc_name = "github-events-limiter"

# Lock file to ensure only one worker starts periodic tasks
_lock_file_path = os.path.join(tempfile.gettempdir(), "gunicorn_periodic_tasks.lock")
_lock_file = None

# Worker lifecycle hooks


def post_fork(server, worker):
    """
    Called after a worker has been forked.
    Start periodic tasks in only the first worker using a file lock.
    """
    global _lock_file

    # Try to acquire exclusive lock
    try:
        _lock_file = open(_lock_file_path, "w")
        fcntl.flock(_lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore

        # We got the lock! This worker will handle periodic tasks
        server.log.info(
            f"Worker {worker.pid}: Acquired lock - this worker will handle periodic tasks"
        )

        try:
            from main import task_manager

            task_manager.start_all_tasks()
            server.log.info(f"Worker {worker.pid}: Periodic tasks started successfully")
        except Exception as e:
            server.log.error(f"Worker {worker.pid}: Failed to start periodic tasks: {e}")
            # Release lock on failure
            fcntl.flock(_lock_file.fileno(), fcntl.LOCK_UN)  # type: ignore
            _lock_file.close()
            _lock_file = None

    except (IOError, OSError):
        # Lock already held by another worker
        server.log.info(
            f"Worker {worker.pid}: Regular worker (periodic tasks handled by another worker)"
        )
        if _lock_file:
            _lock_file.close()
            _lock_file = None


def on_starting(server):
    """Called before the master process is initialized."""
    server.log.info("Gunicorn master process starting")


def on_reload(server):
    """Called on reload."""
    server.log.info("Gunicorn reloading")


def when_ready(server):
    """Called after the server is started."""
    server.log.info(f"Gunicorn ready with {workers} workers")


def worker_exit(server, worker):
    """
    Called when a worker is about to exit.
    Perform WAL checkpoint and truncate before worker shutdown.
    """
    server.log.info(f"Worker {worker.pid}: Shutting down")

    try:
        # Import here to avoid circular dependency issues
        from main import db_handler, db_info, db_type

        # Run WAL checkpoint before closing connections (SQLite only)
        if db_type == "sqlite" and isinstance(db_handler, SQLiteDatabaseHandler):
            server.log.info(f"Worker {worker.pid}: Running database WAL checkpoint...")

            # First, close the db_handler's connection
            db_handler.close()
            server.log.info(f"Worker {worker.pid}: Database connections closed")

            # Now perform TRUNCATE checkpoint with a new connection to actually remove WAL/SHM files
            server.log.info(f"Worker {worker.pid}: Truncating WAL file...")
            conn = sqlite3.connect(db_info)  # db_info is the SQLite path when db_type is "sqlite"
            try:
                # TRUNCATE mode: checkpoint and remove WAL/SHM files
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                server.log.info(f"Worker {worker.pid}: WAL checkpoint and truncate completed")
            finally:
                conn.close()
        else:
            # PostgreSQL or other database - just close connections
            server.log.info(f"Worker {worker.pid}: Closing database connections...")
            db_handler.close()
            server.log.info(f"Worker {worker.pid}: Database connections closed")

    except Exception as e:
        server.log.error(f"Worker {worker.pid}: Error during shutdown: {e}")


def on_exit(server):
    """Called on exit."""
    global _lock_file

    # Clean up lock file
    if _lock_file:
        try:
            fcntl.flock(_lock_file.fileno(), fcntl.LOCK_UN)  # type: ignore
            _lock_file.close()
        except Exception:  # pylint: disable=broad-except
            pass
        _lock_file = None

    # Remove lock file
    try:
        if os.path.exists(_lock_file_path):
            os.unlink(_lock_file_path)
    except Exception:  # pylint: disable=broad-except
        pass

    server.log.info("Gunicorn shutting down")
