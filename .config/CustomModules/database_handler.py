"""
Database Handler Module

Provides database utilities for SQLite and PostgreSQL operations.
"""

import sqlite3
from typing import Optional
from urllib.parse import urlparse


class SQLiteDatabaseHandler:
    """
    Handler for SQLite database operations with connection management.
    """

    def __init__(self, db_path: str, logger=None):
        """
        Initialize the SQLite database handler.

        Args:
            db_path: Path to the SQLite database file
            logger: Logger instance for debug/error logging (optional)
        """
        self.db_path = db_path
        self.logger = logger

    def execute(
        self, query: str, params: tuple = (), commit: bool = False, fetch: bool = False
    ) -> Optional[list]:
        """
        Execute a SQL query.

        Args:
            query: SQL query to execute
            params: Query parameters
            commit: Whether to commit the transaction
            fetch: Whether to fetch and return results

        Returns:
            List of results if fetch=True, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            cursor.execute(query, params)
            if commit:
                conn.commit()
            if fetch:
                results = [dict(row) for row in cursor.fetchall()]
                return results
            return None
        finally:
            conn.close()

    def close(self):
        """
        Close method for compatibility with SyncDatabaseHandler.

        SQLite connections are opened and closed per-query in the execute() method,
        so this method is a no-op for compatibility with code that expects a close() method.
        """
        if self.logger:
            self.logger.debug("SQLite handler close() called (no-op - connections are per-query)")


class SyncDatabaseHandler:
    """
    Synchronous database handler for PostgreSQL operations.
    Supports connection pooling and proper PostgreSQL query execution.
    """

    def __init__(self, connection_string: str, logger=None):
        """
        Initialize the sync database handler for PostgreSQL.

        Args:
            connection_string: PostgreSQL connection string (postgresql://user:pass@host:port/db)
            logger: Logger instance for debug/error logging (optional)
        """
        self.connection_string = connection_string
        self.logger = logger
        self.pool = None

        # Import psycopg here to avoid import errors when PostgreSQL is not used
        try:
            import psycopg
            from psycopg_pool import ConnectionPool

            self.psycopg = psycopg

            # Create connection pool
            parsed = urlparse(connection_string)
            self.pool = ConnectionPool(
                conninfo=connection_string, min_size=1, max_size=10, timeout=30
            )
            if logger:
                logger.debug(
                    f"PostgreSQL connection pool created for "
                    f"{parsed.hostname}:{parsed.port}/{parsed.path[1:]}"
                )
        except ImportError as e:
            if logger:
                logger.error(f"Failed to import psycopg: {e}")
            raise

    @classmethod
    def create(cls, connection_string: str, logger=None):
        """
        Factory method to create a SyncDatabaseHandler instance.

        Args:
            connection_string: PostgreSQL connection string
            logger: Logger instance for debug/error logging (optional)

        Returns:
            SyncDatabaseHandler instance
        """
        return cls(connection_string, logger)

    def execute(
        self, query: str, params: tuple = (), commit: bool = False, fetch: bool = False
    ) -> Optional[list]:
        """
        Execute a SQL query on PostgreSQL.

        Args:
            query: SQL query to execute
            params: Query parameters
            commit: Whether to commit the transaction
            fetch: Whether to fetch and return results

        Returns:
            List of results if fetch=True, None otherwise
        """
        if not self.pool:
            if self.logger:
                self.logger.error("Database pool not initialized")
            return None

        try:
            with self.pool.connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, params)
                    if commit:
                        conn.commit()
                    if fetch:
                        # Fetch all results and convert to list of dicts
                        columns = (
                            [desc[0] for desc in cursor.description] if cursor.description else []
                        )
                        results = []
                        for row in cursor.fetchall():
                            results.append(dict(zip(columns, row)))
                        return results
                    return None
        except Exception as e:
            if self.logger:
                self.logger.error(f"Database query error: {e}")
            raise

    def close(self):
        """Close the connection pool."""
        if self.pool:
            self.pool.close()
            if self.logger:
                self.logger.debug("PostgreSQL connection pool closed")
