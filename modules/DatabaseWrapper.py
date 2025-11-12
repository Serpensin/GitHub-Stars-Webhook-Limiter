"""
Database Wrapper Module

Provides a unified interface for database operations across SQLite and PostgreSQL.
Automatically handles SQL syntax differences between database engines.
"""

import time
from typing import Literal, Optional


class DatabaseWrapper:
    """
    Wrapper for database operations that abstracts away differences between SQLite and PostgreSQL.

    Handles:
    - Timestamp conversions (Unix epoch <-> TIMESTAMP type)
    - SQL syntax differences (ON CONFLICT vs ON DUPLICATE KEY UPDATE)
    - Query construction based on database type
    """

    def __init__(self, db_type: Literal["sqlite", "postgresql"]):
        """
        Initialize the database wrapper.

        Args:
            db_type: Either "sqlite" or "postgresql"
        """
        self.db_type = db_type

    def timestamp_placeholder(self) -> str:
        """
        Get the correct placeholder for inserting Unix timestamps.

        Returns:
            "to_timestamp(?)" for PostgreSQL, "?" for SQLite
        """
        return "to_timestamp(?)" if self.db_type == "postgresql" else "?"

    def timestamp_value(self, unix_timestamp: Optional[int] = None) -> int:
        """
        Get the current or specified Unix timestamp.

        Args:
            unix_timestamp: Optional Unix timestamp. If None, uses current time.

        Returns:
            Unix timestamp as integer
        """
        return unix_timestamp if unix_timestamp is not None else int(time.time())

    def build_insert_cleanup_task(self) -> str:
        """
        Build INSERT...ON CONFLICT query for cleanup_tasks table.

        Returns:
            SQL query string
        """
        if self.db_type == "postgresql":
            return """
                INSERT INTO cleanup_tasks (task_name, last_run)
                VALUES (?, to_timestamp(?))
                ON CONFLICT(task_name) DO UPDATE SET last_run = to_timestamp(?)
            """
        else:  # sqlite
            return """
                INSERT INTO cleanup_tasks (task_name, last_run)
                VALUES (?, ?)
                ON CONFLICT(task_name) DO UPDATE SET last_run = ?
            """

    def build_update_repository_timestamp(self, field: str) -> str:
        """
        Build UPDATE query for repository timestamp fields.

        Args:
            field: Field name (e.g., "last_webhook_checked", "last_repo_checked")

        Returns:
            SQL query string
        """
        if self.db_type == "postgresql":
            return f"UPDATE repositories SET {field} = to_timestamp(?) WHERE "
        else:
            return f"UPDATE repositories SET {field} = ? WHERE "

    def build_timestamp_comparison(self, field: str, operator: str = "<") -> str:
        """
        Build timestamp comparison clause for WHERE conditions.

        Args:
            field: Field name to compare
            operator: Comparison operator (default: "<")

        Returns:
            SQL comparison string (e.g., "field < to_timestamp(?)" or "field < ?")
        """
        if self.db_type == "postgresql":
            return f"{field} {operator} to_timestamp(?)"
        else:
            return f"{field} {operator} ?"

    def build_delete_old_rate_limits(self) -> str:
        """
        Build DELETE query for expired rate limit entries.

        Returns:
            SQL query string
        """
        if self.db_type == "postgresql":
            return """
                DELETE FROM api_rate_limit_tracking
                WHERE first_request_time < to_timestamp(?)
            """
        else:
            return """
                DELETE FROM api_rate_limit_tracking
                WHERE first_request_time < ?
            """

    def build_select_webhooks_to_check(self) -> str:
        """
        Build SELECT query for webhooks needing verification.

        Returns:
            SQL query string
        """
        if self.db_type == "postgresql":
            return """
                SELECT DISTINCT discord_webhook_url
                FROM repositories
                WHERE last_webhook_checked IS NULL OR last_webhook_checked < to_timestamp(?)
            """
        else:
            return """
                SELECT DISTINCT discord_webhook_url
                FROM repositories
                WHERE last_webhook_checked IS NULL OR last_webhook_checked < ?
            """

    def build_select_repos_to_check(self) -> str:
        """
        Build SELECT query for repositories needing verification.

        Returns:
            SQL query string
        """
        if self.db_type == "postgresql":
            return """
                SELECT repo_id, repo_full_name, discord_webhook_url, last_event_received
                FROM repositories
                WHERE last_repo_checked IS NULL OR last_repo_checked < to_timestamp(?)
            """
        else:
            return """
                SELECT repo_id, repo_full_name, discord_webhook_url, last_event_received
                FROM repositories
                WHERE last_repo_checked IS NULL OR last_repo_checked < ?
            """

    def build_select_inactive_api_keys(self) -> str:
        """
        Build SELECT query for inactive API keys.

        Returns:
            SQL query string
        """
        if self.db_type == "postgresql":
            return """
                SELECT id, name, last_used, created_at
                FROM api_keys
                WHERE is_admin_key = 0
                AND (
                    (last_used IS NOT NULL AND last_used < to_timestamp(?))
                    OR (last_used IS NULL AND created_at < to_timestamp(?))
                )
            """
        else:
            return """
                SELECT id, name, last_used, created_at
                FROM api_keys
                WHERE is_admin_key = 0
                AND (
                    (last_used IS NOT NULL AND last_used < ?)
                    OR (last_used IS NULL AND created_at < ?)
                )
            """

    def build_increment_statistic(self) -> str:
        """
        Build INSERT...ON CONFLICT query for incrementing statistics.

        Returns:
            SQL query string
        """
        if self.db_type == "postgresql":
            return """
                INSERT INTO statistics (stat_name, stat_value)
                VALUES (?, ?)
                ON CONFLICT(stat_name) DO UPDATE SET
                    stat_value = statistics.stat_value + EXCLUDED.stat_value
            """
        else:  # sqlite
            return """
                INSERT INTO statistics (stat_name, stat_value)
                VALUES (?, ?)
                ON CONFLICT(stat_name) DO UPDATE SET
                    stat_value = stat_value + excluded.stat_value
            """

    def build_increment_statistic_by_one(self) -> str:
        """
        Build INSERT...ON CONFLICT query for incrementing a statistic by 1.

        Returns:
            SQL query string
        """
        if self.db_type == "postgresql":
            return """
                INSERT INTO statistics (stat_name, stat_value)
                VALUES (?, 1)
                ON CONFLICT(stat_name) DO UPDATE SET
                    stat_value = statistics.stat_value + 1
            """
        else:  # sqlite
            return """
                INSERT INTO statistics (stat_name, stat_value)
                VALUES (?, 1)
                ON CONFLICT(stat_name) DO UPDATE SET
                    stat_value = stat_value + 1
            """

    def build_upsert_user_statistics_valid(self) -> str:
        """
        Build INSERT...ON CONFLICT query for valid event user statistics.

        Returns:
            SQL query string
        """
        if self.db_type == "postgresql":
            return """
                INSERT INTO user_statistics (
                    github_user_id, github_username, valid_events, last_event_timestamp
                )
                VALUES (?, ?, 1, to_timestamp(?))
                ON CONFLICT(github_user_id) DO UPDATE SET
                    github_username = EXCLUDED.github_username,
                    valid_events = user_statistics.valid_events + 1,
                    last_event_timestamp = EXCLUDED.last_event_timestamp
            """
        else:  # sqlite
            return """
                INSERT INTO user_statistics (
                    github_user_id, github_username, valid_events, last_event_timestamp
                )
                VALUES (?, ?, 1, ?)
                ON CONFLICT(github_user_id) DO UPDATE SET
                    github_username = excluded.github_username,
                    valid_events = valid_events + 1,
                    last_event_timestamp = excluded.last_event_timestamp
            """

    def build_upsert_user_statistics_invalid(self) -> str:
        """
        Build INSERT...ON CONFLICT query for invalid event user statistics.

        Returns:
            SQL query string
        """
        if self.db_type == "postgresql":
            return """
                INSERT INTO user_statistics (
                    github_user_id, github_username, invalid_events, last_event_timestamp
                )
                VALUES (?, ?, 1, to_timestamp(?))
                ON CONFLICT(github_user_id) DO UPDATE SET
                    github_username = EXCLUDED.github_username,
                    invalid_events = user_statistics.invalid_events + 1,
                    last_event_timestamp = EXCLUDED.last_event_timestamp
            """
        else:  # sqlite
            return """
                INSERT INTO user_statistics (
                    github_user_id, github_username, invalid_events, last_event_timestamp
                )
                VALUES (?, ?, 1, ?)
                ON CONFLICT(github_user_id) DO UPDATE SET
                    github_username = excluded.github_username,
                    invalid_events = invalid_events + 1,
                    last_event_timestamp = excluded.last_event_timestamp
            """
