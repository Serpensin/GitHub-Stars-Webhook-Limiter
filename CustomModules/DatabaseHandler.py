"""
Database Handler Module

Provides centralized database connection management with WAL mode,
optimizations, and thread-safe access for the GitHub Events Limiter.

Usage:
    from CustomModules.DatabaseHandler import DatabaseHandler

    db_handler = DatabaseHandler("GitHub_Events_Limiter/data.db", logger)

    # Execute query
    result = db_handler.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,))

    # Execute with commit
    db_handler.execute("INSERT INTO ...", params, commit=True)

    # Get connection for complex operations
    with db_handler.get_connection() as conn:
        cursor = conn.cursor()
        # ... operations ...
        conn.commit()
"""

import logging
import sqlite3
import threading
from contextlib import contextmanager
from typing import List, Optional, Tuple


class DatabaseHandler:
    """
    Thread-safe database handler with connection pooling and optimization.
    """

    def __init__(self, db_path: str, logger=None):
        """
        Initialize database handler.

        Args:
            db_path: Path to the SQLite database file
            logger: Logger instance for debug/error logging (optional)
        """
        self.db_path = db_path

        # Initialize logger
        if logger is None:
            self.logger = logging.getLogger("custommodules.databasehandler")
        else:
            self.logger = logger.getChild("custommodules.databasehandler")

        self._local = threading.local()
        self._lock = threading.Lock()

        # Initialize database with optimizations
        self._initialize_database()

    def _initialize_database(self):
        """Initialize database with WAL mode and optimizations."""
        try:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row

            # Enable WAL mode for better concurrent performance
            conn.execute("PRAGMA journal_mode=WAL")

            # Optimize SQLite performance
            conn.execute("PRAGMA synchronous=NORMAL")  # Faster than FULL, safe with WAL
            conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
            conn.execute("PRAGMA temp_store=MEMORY")  # Store temp tables in memory
            conn.execute("PRAGMA mmap_size=268435456")  # 256MB memory-mapped I/O
            conn.execute("PRAGMA busy_timeout=5000")  # Wait up to 5s for locks

            conn.close()

            if self.logger:
                self.logger.debug(f"Database initialized with WAL mode: {self.db_path}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Database initialization error: {e}")
            raise

    def _get_thread_connection(self) -> sqlite3.Connection:
        """
        Get or create a connection for the current thread.

        Returns:
            SQLite connection for this thread
        """
        if not hasattr(self._local, "connection") or self._local.connection is None:
            self._local.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.connection.row_factory = sqlite3.Row

            # Apply optimizations to this connection
            self._local.connection.execute("PRAGMA journal_mode=WAL")
            self._local.connection.execute("PRAGMA synchronous=NORMAL")
            self._local.connection.execute("PRAGMA cache_size=-64000")
            self._local.connection.execute("PRAGMA temp_store=MEMORY")
            self._local.connection.execute("PRAGMA mmap_size=268435456")
            self._local.connection.execute("PRAGMA busy_timeout=5000")

            if self.logger:
                self.logger.debug(
                    f"Created new database connection for thread {threading.current_thread().name}"
                )

        return self._local.connection

    @contextmanager
    def get_connection(self):
        """
        Context manager for getting a database connection.

        Usage:
            with db_handler.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ...")
                conn.commit()

        Yields:
            SQLite connection
        """
        conn = self._get_thread_connection()
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            if self.logger:
                self.logger.error(f"Database operation error, rolled back: {e}")
            raise

    def execute(
        self, query: str, params: Optional[Tuple] = None, commit: bool = False, fetch: str = None
    ) -> Optional[List[sqlite3.Row]]:
        """
        Execute a database query.

        Args:
            query: SQL query to execute
            params: Query parameters (optional)
            commit: Whether to commit after execution (default: False)
            fetch: Fetch mode - 'one', 'all', or None (default: None)

        Returns:
            Query results if fetch is specified, None otherwise
        """
        conn = self._get_thread_connection()
        cursor = conn.cursor()

        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            result = None
            if fetch == "one":
                result = cursor.fetchone()
            elif fetch == "all":
                result = cursor.fetchall()
            elif fetch is False:
                # For DELETE/UPDATE/INSERT, return the number of affected rows
                result = cursor.rowcount

            if commit:
                conn.commit()
                if self.logger:
                    self.logger.debug("Committed transaction")

            return result

        except Exception as e:
            conn.rollback()
            if self.logger:
                self.logger.error(f"Query execution error: {e}")
            raise

    def execute_many(self, query: str, params_list: List[Tuple], commit: bool = True) -> int:
        """
        Execute a query multiple times with different parameters.

        Args:
            query: SQL query to execute
            params_list: List of parameter tuples
            commit: Whether to commit after execution (default: True)

        Returns:
            Number of affected rows
        """
        conn = self._get_thread_connection()
        cursor = conn.cursor()

        try:
            cursor.executemany(query, params_list)
            rowcount = cursor.rowcount

            if commit:
                conn.commit()
                if self.logger:
                    self.logger.debug(f"Committed batch transaction: {rowcount} rows affected")

            return rowcount

        except Exception as e:
            conn.rollback()
            if self.logger:
                self.logger.error(f"Batch query execution error: {e}")
            raise

    def close_thread_connection(self):
        """Close the database connection for the current thread."""
        if hasattr(self._local, "connection") and self._local.connection is not None:
            self._local.connection.close()
            self._local.connection = None
            if self.logger:
                self.logger.debug(
                    f"Closed database connection for thread {threading.current_thread().name}"
                )

    def close_all_connections(self):
        """Close all database connections (call on shutdown)."""
        # This is tricky because connections are thread-local
        # Best approach is to let threads close their own connections
        if hasattr(self._local, "connection") and self._local.connection is not None:
            self._local.connection.close()
            self._local.connection = None

    def checkpoint_wal(self):
        """Run a WAL checkpoint to flush all changes to the main .db file."""
        try:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.execute("PRAGMA wal_checkpoint(FULL);")
            conn.close()
            if self.logger:
                self.logger.info("WAL checkpoint completed and changes flushed to .db file.")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error running WAL checkpoint: {e}")
            raise
