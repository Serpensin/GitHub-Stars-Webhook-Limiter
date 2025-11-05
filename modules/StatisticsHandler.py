"""
Statistics Handler Module

Provides utilities for tracking and retrieving application statistics.

Usage:
    from modules.StatisticsHandler import StatisticsHandler

    stats_handler = StatisticsHandler(
        get_db_func=get_db,
        logger=logger
    )

    # Increment a statistic
    stats_handler.increment_stat("api_requests", amount=1)

    # Get a statistic value
    value = stats_handler.get_stat("api_requests")

    # Get all statistics
    all_stats = stats_handler.get_all_stats()

    # Get top users
    top_users = stats_handler.get_top_users(event_type="valid", limit=10)
"""

import logging
import sqlite3
from typing import Callable


class StatisticsHandler:
    """
    Handles statistics tracking and retrieval for application metrics.
    """

    def __init__(
        self,
        get_db_func: Callable,
        logger=None,
    ):
        """
        Initialize the statistics handler.

        Args:
            get_db_func: Function that returns a database connection
            logger: Optional logger instance for debug/error messages
        """
        self.get_db = get_db_func
        # Initialize logger
        if logger is None:
            self.logger = logging.getLogger("modules.statisticshandler")
        else:
            self.logger = logger.getChild("modules.statisticshandler")

    def increment_stat(
        self,
        stat_name: str,
        amount: int = 1,
    ) -> None:
        """
        Increment a statistic counter by a specified amount.

        Args:
            stat_name: The name of the statistic to increment
            amount: The amount to increment by (default: 1)
        """
        try:
            db = self.get_db()
            db.execute(
                """
                INSERT INTO statistics (stat_name, stat_value, last_updated)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(stat_name) DO UPDATE SET
                    stat_value = stat_value + ?,
                    last_updated = CURRENT_TIMESTAMP
                """,
                (stat_name, amount, amount),
            )
            if self.logger:
                self.logger.debug(f"Incremented statistic '{stat_name}' by {amount}")
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Database error incrementing statistic '{stat_name}': {e}")

    def get_stat(
        self,
        stat_name: str,
    ) -> int:
        """
        Get the current value of a statistic.

        Args:
            stat_name: The name of the statistic to retrieve

        Returns:
            The current value of the statistic, or 0 if not found
        """
        try:
            db = self.get_db()
            cursor = db.execute(
                "SELECT stat_value FROM statistics WHERE stat_name = ? LIMIT 1",
                (stat_name,),
            )
            row = cursor.fetchone()
            return row["stat_value"] if row else 0
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Database error getting statistic '{stat_name}': {e}")
            return 0

    def get_all_stats(
        self,
    ) -> dict:
        """
        Get all statistics as a dictionary.

        Returns:
            Dictionary mapping stat_name to stat_value
        """
        try:
            db = self.get_db()
            cursor = db.execute("SELECT stat_name, stat_value FROM statistics")
            return {row["stat_name"]: row["stat_value"] for row in cursor.fetchall()}
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Database error getting all statistics: {e}")
            return {}

    def get_top_users(
        self,
        event_type: str = "valid",
        limit: int = 10,
    ) -> list[dict]:
        """
        Get top users by event count.

        Args:
            event_type: Either 'valid' or 'invalid' to specify which events to count
            limit: Maximum number of users to return (default: 10)

        Returns:
            List of dictionaries with user_id, username, and count
        """
        try:
            db = self.get_db()
            column = "valid_events" if event_type == "valid" else "invalid_events"
            # Use parameterized query safely
            query = f"""
                SELECT github_user_id, github_username, {column} as count
                FROM user_statistics
                WHERE {column} > 0
                ORDER BY {column} DESC
                LIMIT ?
                """
            cursor = db.execute(query, (limit,))
            return [
                {
                    "user_id": row["github_user_id"],
                    "username": row["github_username"],
                    "count": row["count"],
                }
                for row in cursor.fetchall()
            ]
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Database error getting top users: {e}")
            return []
