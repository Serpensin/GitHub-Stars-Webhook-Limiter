"""
Periodic background tasks for the GitHub Stars Webhook Limiter.
These tasks run on a schedule to maintain database health.

Usage:
    from periodic_tasks import PeriodicTaskManager
    from CustomModules.DatabaseHandler import DatabaseHandler
    from modules.DiscordHandler import DiscordHandler
    from modules.GitHubHandler import GitHubHandler

    db_handler = DatabaseHandler("GitHub_Events_Limiter/data.db", logger)
    discord_handler = DiscordHandler(logger=logger)
    github_handler = GitHubHandler(logger=logger)

    task_manager = PeriodicTaskManager(
        db_handler=db_handler,
        log_manager=log_manager,
        discord_handler=discord_handler,
        github_handler=github_handler
    )
    task_manager.start_all_tasks()
"""

import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

from CustomModules.database_handler import SQLiteDatabaseHandler
from CustomModules.log_handler import LogManager

# Import config module
config_path = Path(__file__).parent.parent / ".config"
if str(config_path) not in sys.path:
    sys.path.insert(0, str(config_path))
import config  # type: ignore  # noqa: E402

# SQL query constants to avoid duplication
_SQL_GET_LAST_RUN = "SELECT last_run FROM cleanup_tasks WHERE task_name = ?"
_SQL_UPDATE_LAST_RUN = """
    INSERT INTO cleanup_tasks (task_name, last_run)
    VALUES (?, ?)
    ON CONFLICT(task_name) DO UPDATE SET last_run = ?
    """


class PeriodicTaskManager:
    """
    Manages periodic background tasks with configurable intervals.

    To add a new task:
    1. Create a method for your task logic
    2. Add it to the tasks list in __init__ with its interval
    3. The task will automatically run when start_all_tasks() is called
    """

    def __init__(
        self,
        db_handler: SQLiteDatabaseHandler,
        log_manager: LogManager,
        discord_handler,
        github_handler,
        log_name: str = "periodic_tasks",
        send_discord_notification=None,
        db_path: Optional[str] = None,
    ):
        """
        Initialize the periodic task manager.

        Args:
            db_handler: DatabaseHandler instance for database operations
            log_manager: LogManager instance for creating logger
            discord_handler: DiscordHandler instance for Discord webhook operations
            github_handler: GitHubHandler instance for GitHub API operations
            log_name: Name for the logger (default: "periodic_tasks")
            send_discord_notification: Function to send Discord notifications for cleanup
            db_path: Path to the SQLite database file for direct access
        """
        self.db_handler = db_handler
        self.db_path = db_path  # Store the database path for direct SQLite access
        self.log_manager = log_manager
        self.log_name = log_name
        self.logger = log_manager.get_logger(log_name)
        self.send_discord_notification = send_discord_notification
        self.running_threads = []
        self.task_loggers = {}  # Store loggers for each task
        self.tasks_started = False  # Flag to prevent starting tasks multiple times

        # Store handler instances passed from main.py
        self.discord_handler = discord_handler
        self.github_handler = github_handler

        # Register all tasks here - they will automatically start when start_all_tasks() is called
        # Format: self.register_task(method, interval_seconds, "Task Name")
        self.tasks = []
        self.register_task(self.cleanup_expired_rate_limits, 60, "Rate Limit Cleanup")
        self.register_task(self.cleanup_discord_webhooks, 60, "Discord Webhook Cleanup")
        self.register_task(self.cleanup_inactive_repositories, 60, "Repository Cleanup")
        self.register_task(self.cleanup_inactive_api_keys, 60, "API Key Cleanup")
        # Add more tasks here - just create the method below and register it:
        # self.register_task(self.cleanup_old_logs, 3600, "Log Cleanup")
        # self.register_task(self.backup_database, 86400, "Database Backup")

    def register_task(self, task_func, interval: int, task_name: str) -> None:
        """
        Register a periodic task. Called during initialization.

        Args:
            task_func: The function to run periodically
            interval: How often to run the task (in seconds)
            task_name: Human-readable name for the task
        """
        # Create a logger for this specific task
        logger_name = f"{self.log_name}.{task_name.replace(' ', '_')}"
        task_logger = self.log_manager.get_logger(logger_name)
        self.task_loggers[task_name] = task_logger

        self.tasks.append((task_func, interval, task_name))

    def cleanup_expired_rate_limits(self, logger) -> None:
        """
        Delete expired API rate limit tracking entries (older than 1 hour).
        Runs every 60 seconds but cleanup is very lightweight.

        Args:
            logger: Logger instance for this task
        """
        try:
            # Calculate the cutoff time (1 hour ago)
            one_hour_ago = int(time.time()) - 3600

            # Delete entries where first request was more than 1 hour ago
            deleted_count = self._execute_sql(
                """
                DELETE FROM api_rate_limit_tracking
                WHERE first_request_time < ?
                """,
                (one_hour_ago,),
            )

            # Type assertion: when not fetching, _execute_sql returns int (rowcount)
            assert isinstance(deleted_count, int)

            if deleted_count > 0:
                if logger:
                    logger.info(f"Cleaned up {deleted_count} expired rate limit entries")
            else:
                if logger:
                    logger.debug("No expired rate limit entries to clean up")

        except Exception as e:
            if logger:
                logger.error(f"Error during rate limit cleanup: {e}")
                logger.error(f"Error during rate limit cleanup: {e}")

    def cleanup_discord_webhooks(self, logger) -> None: # NOSONAR
        """
        Check Discord webhooks that haven't been checked in 28 days and verify they still exist.
        Runs once every 4 hours. Deletes repository entries if webhook is invalid.

        Args:
            logger: Logger instance for this task
        """
        try:
            # Check if this task ran in the last 4 hours
            last_run = self._execute_sql(
                _SQL_GET_LAST_RUN,
                ("webhook_cleanup",),
                fetch_one=True,
            )

            if last_run:
                assert isinstance(last_run, dict)
                last_run_time = last_run["last_run"]
                four_hours_ago = int(time.time()) - (4 * 3600)
                if last_run_time > four_hours_ago:
                    if logger:
                        logger.debug("Webhook cleanup skipped (ran recently)")
                    return

            if logger:
                logger.info("Starting Discord webhook cleanup task")

            # Find unique webhook URLs that need checking (last_webhook_checked > 28 days or NULL)
            twenty_eight_days_ago = int(time.time()) - (28 * 86400)
            webhooks_to_check = self._execute_sql(
                """
                SELECT DISTINCT discord_webhook_url
                FROM repositories
                WHERE last_webhook_checked IS NULL OR last_webhook_checked < ?
                """,
                (twenty_eight_days_ago,),
                fetch_all=True,
            )

            if not webhooks_to_check:
                if logger:
                    logger.debug("No webhooks need checking")
                self._execute_sql(
                    _SQL_UPDATE_LAST_RUN,
                    ("webhook_cleanup", int(time.time()), int(time.time())),
                )
                return

            # Type assertion: fetch_all returns list
            assert isinstance(webhooks_to_check, list)

            checked_count = 0
            deleted_count = 0

            for row in webhooks_to_check:
                webhook_url = row["discord_webhook_url"]

                try:
                    # Validate Discord webhook URL to prevent SSRF
                    # Only allow official Discord webhook URLs
                    if not webhook_url.startswith(
                        "https://discord.com/api/webhooks/"
                    ) and not webhook_url.startswith("https://discordapp.com/api/webhooks/"):
                        if logger:
                            logger.warning(
                                f"Invalid Discord webhook URL format: {webhook_url[:50]}..."
                            )
                        continue

                    # Check if Discord webhook still exists using DiscordHandler
                    is_valid = self.discord_handler.verify_webhook(webhook_url)

                    if is_valid:
                        # Webhook is valid - update last_webhook_checked
                        self._execute_sql(
                            (
                                "UPDATE repositories SET last_webhook_checked = ? "
                                "WHERE discord_webhook_url = ?"
                            ),
                            (int(time.time()), webhook_url),
                        )
                        checked_count += 1
                        if logger:
                            logger.debug(f"Webhook verified: {webhook_url[:50]}...")

                    else:
                        # Webhook no longer exists - send notification and delete entries
                        if logger:
                            logger.warning(f"Webhook no longer valid: {webhook_url[:50]}...")

                        # Get all repositories using this webhook
                        repos = self._execute_sql(
                            "SELECT repo_full_name FROM repositories WHERE discord_webhook_url = ?",
                            (webhook_url,),
                            fetch_all=True,
                        )

                        # Type assertion: fetch_all returns list
                        assert isinstance(repos, list)

                        # Send farewell notification to the webhook (best effort)
                        if self.send_discord_notification and repos:
                            try:
                                repo_list = (
                                    ", ".join([r["repo_full_name"] for r in repos])
                                    if repos
                                    else "unknown"
                                )
                                self.send_discord_notification(
                                    webhook_url,
                                    cleanup_type="webhook_deleted",
                                    repo_name=repo_list,
                                    reason="Discord webhook is no longer valid",
                                )
                            except Exception:
                                pass  # Silently ignore notification errors

                        # Delete all repositories using this webhook
                        deleted_repos = self._execute_sql(
                            "DELETE FROM repositories WHERE discord_webhook_url = ?",
                            (webhook_url,),
                        )

                        # Type assertion: DELETE returns int (rowcount)
                        assert isinstance(deleted_repos, int)
                        deleted_count += deleted_repos

                        # Increment deletion statistic
                        self._execute_sql(
                            """
                            INSERT INTO statistics (stat_name, stat_value)
                            VALUES ('repos_deleted_webhook_invalid', ?)
                            ON CONFLICT(stat_name) DO UPDATE SET
                                stat_value = stat_value + ?
                            """,
                            (deleted_repos, deleted_repos),
                        )

                        if logger:
                            logger.info(
                                f"Deleted {deleted_repos} repositories with invalid webhook"
                            )

                except Exception as e:
                    # Error checking webhook - skip this webhook
                    if logger:
                        logger.debug(f"Failed to check webhook (will retry later): {e}")
                    continue

            if logger:
                logger.info(
                    (
                        f"Webhook cleanup complete: checked {checked_count}, "
                        f"deleted {deleted_count} repos"
                    )
                )

            # Update last run time
            self._execute_sql(
                _SQL_UPDATE_LAST_RUN,
                ("webhook_cleanup", int(time.time()), int(time.time())),
            )

        except Exception as e:
            if logger:
                logger.error(f"Error during webhook cleanup: {e}")

    def cleanup_inactive_repositories(self, logger) -> None: # NOSONAR
        """
        Check repositories that haven't received events in 360+ days and verify they still exist.
        Runs once every 4 hours. Deletes repository entries if inactive or deleted.

        Args:
            logger: Logger instance for this task
        """
        try:
            # Check if this task ran in the last 4 hours
            last_run = self._execute_sql(
                _SQL_GET_LAST_RUN,
                ("repo_cleanup",),
                fetch_one=True,
            )

            if last_run:
                assert isinstance(last_run, dict)
                last_run_time = last_run["last_run"]
                four_hours_ago = int(time.time()) - (4 * 3600)
                if last_run_time > four_hours_ago:
                    if logger:
                        logger.debug("Repository cleanup skipped (ran recently)")
                    return

            if logger:
                logger.info("Starting repository cleanup task")

            # Find repositories that need checking (last_repo_checked > 28 days or NULL)
            twenty_eight_days_ago = int(time.time()) - (28 * 86400)
            repos_to_check = self._execute_sql(
                """
                SELECT repo_id, repo_full_name, discord_webhook_url, last_event_received
                FROM repositories
                WHERE last_repo_checked IS NULL OR last_repo_checked < ?
                """,
                (twenty_eight_days_ago,),
                fetch_all=True,
            )

            if not repos_to_check:
                if logger:
                    logger.debug("No repositories need checking")
                self._execute_sql(
                    _SQL_UPDATE_LAST_RUN,
                    ("repo_cleanup", int(time.time()), int(time.time())),
                )
                return

            # Type assertion: fetch_all returns list
            assert isinstance(repos_to_check, list)

            checked_count = 0
            deleted_inactive_count = 0
            deleted_gone_count = 0

            for repo_row in repos_to_check:
                repo_id = repo_row["repo_id"]
                repo_name = repo_row["repo_full_name"]
                last_event = repo_row["last_event_received"]
                discord_webhook_url = repo_row["discord_webhook_url"]

                # Check if repository hasn't received events in configured days
                if last_event:
                    days_since_event = (int(time.time()) - last_event) // 86400
                    if days_since_event >= config.CLEANUP_INACTIVE_REPOSITORIES_DAYS:
                        # Repository is inactive - delete it
                        if logger:
                            logger.warning(
                                "Deleting inactive repository (%s days): %s",
                                days_since_event,
                                repo_name,
                            )

                        # Send notification to Discord webhook
                        if self.send_discord_notification:
                            try:
                                self.send_discord_notification(
                                    discord_webhook_url,
                                    cleanup_type="repo_inactive",
                                    repo_name=repo_name,
                                    reason=(
                                        f"No webhook events for {days_since_event} days"
                                        f" (threshold {config.CLEANUP_INACTIVE_REPOSITORIES_DAYS})"
                                    ),
                                )
                            except Exception:
                                pass  # Silently ignore notification errors

                        # Delete the repository
                        self._execute_sql(
                            "DELETE FROM repositories WHERE repo_id = ?",
                            (repo_id,),
                        )
                        deleted_inactive_count += 1

                        # Increment deletion statistic
                        self._execute_sql(
                            """
                            INSERT INTO statistics (stat_name, stat_value)
                            VALUES ('repos_deleted_inactive_360_days', 1)
                            ON CONFLICT(stat_name) DO UPDATE SET
                                stat_value = stat_value + 1
                            """,
                        )
                        continue

                # Repository is not inactive - check if it still exists on GitHub
                try:
                    # Extract owner and repo from repo_name using GitHubHandler
                    repo_info = self.github_handler.extract_repo_info_from_url(
                        f"https://github.com/{repo_name}"
                    )

                    if not repo_info:
                        # Invalid repo name format
                        if logger:
                            logger.warning(f"Invalid repository name format: {repo_name}")
                        continue

                    owner, repo = repo_info

                    # Fetch repository data from GitHub API using GitHubHandler
                    repo_data = self.github_handler.fetch_repo_data(owner, repo)

                    if repo_data:
                        # Repository exists - update last_repo_checked
                        self._execute_sql(
                            "UPDATE repositories SET last_repo_checked = ? WHERE repo_id = ?",
                            (int(time.time()), repo_id),
                        )
                        checked_count += 1
                        if logger:
                            logger.debug(f"Repository verified: {repo_name}")

                    else:
                        # Repository no longer exists (fetch_repo_data returns None for 404)
                        if logger:
                            logger.warning(f"Repository no longer exists: {repo_name}")

                        # Send notification to Discord webhook
                        if self.send_discord_notification:
                            try:
                                self.send_discord_notification(
                                    discord_webhook_url,
                                    cleanup_type="repo_deleted",
                                    repo_name=repo_name,
                                    reason="GitHub repository was deleted or made private",
                                )
                            except Exception:
                                pass  # Silently ignore notification errors

                        # Delete the repository
                        self._execute_sql(
                            "DELETE FROM repositories WHERE repo_id = ?",
                            (repo_id,),
                        )
                        deleted_gone_count += 1

                        # Increment deletion statistic
                        self._execute_sql(
                            """
                            INSERT INTO statistics (stat_name, stat_value)
                            VALUES ('repos_deleted_repo_gone', 1)
                            ON CONFLICT(stat_name) DO UPDATE SET
                                stat_value = stat_value + 1
                            """,
                        )

                except Exception as e:
                    # Error checking repository - skip this repo
                    if logger:
                        logger.debug(
                            "Failed to check repository %s (will retry later): %s",
                            repo_name,
                            e,
                        )
                    continue

            if logger:
                logger.info(
                    f"Repository cleanup complete: checked {checked_count}, "
                    f"deleted inactive {deleted_inactive_count}, gone {deleted_gone_count}"
                )

            # Update last run time
            self._execute_sql(
                """
                INSERT INTO cleanup_tasks (task_name, last_run)
                VALUES (?, ?)
                ON CONFLICT(task_name) DO UPDATE SET last_run = ?
                """,
                ("repo_cleanup", int(time.time()), int(time.time())),
            )

        except Exception as e:
            if logger:
                logger.error(f"Error during repository cleanup: {e}")

    def cleanup_inactive_api_keys(self, logger) -> None: # NOSONAR
        """
        Delete non-admin API keys that haven't been used in 360+ days.
        Runs once every 4 hours.

        Args:
            logger: Logger instance for this task
        """
        try:
            # Check if this task ran in the last 4 hours
            last_run = self._execute_sql(
                _SQL_GET_LAST_RUN,
                ("api_key_cleanup",),
                fetch_one=True,
            )

            if last_run:
                assert isinstance(last_run, dict)
                last_run_time = last_run["last_run"]
                four_hours_ago = int(time.time()) - (4 * 3600)
                if last_run_time > four_hours_ago:
                    if logger:
                        logger.debug("API key cleanup skipped (ran recently)")
                    return

            if logger:
                logger.info("Starting API key cleanup task")

            # Find non-admin API keys that haven't been used in the configured number of days
            # or were created but never used for that period
            days = config.CLEANUP_INACTIVE_API_KEYS_DAYS
            cleanup_threshold = int(time.time()) - (days * 86400)
            inactive_keys = self._execute_sql(
                """
                SELECT id, name, last_used, created_at
                FROM api_keys
                WHERE is_admin_key = 0
                AND (
                    (last_used IS NOT NULL AND last_used < ?)
                    OR (last_used IS NULL AND created_at < ?)
                )
                """,
                (cleanup_threshold, cleanup_threshold),
                fetch_all=True,
            )

            if not inactive_keys:
                if logger:
                    logger.debug("No inactive API keys to delete")
                self._execute_sql(
                    _SQL_UPDATE_LAST_RUN,
                    ("api_key_cleanup", int(time.time()), int(time.time())),
                )
                return

            # Type assertion: fetch_all returns list
            assert isinstance(inactive_keys, list)

            deleted_count = 0

            for key in inactive_keys:
                key_id = key["id"]
                key_name = key["name"]
                last_used = key["last_used"]

                days_inactive = (
                    "never used"
                    if not last_used
                    else f"{(int(time.time()) - last_used) // 86400} days"
                )

                # Delete the API key
                self._execute_sql(
                    "DELETE FROM api_keys WHERE id = ?",
                    (key_id,),
                )
                deleted_count += 1

                if logger:
                    logger.info(
                        (
                            f"Deleted inactive API key (ID: {key_id}, Name: {key_name}, "
                            f"Inactive: {days_inactive})"
                        )
                    )

            # Increment deletion statistic
            if deleted_count > 0:
                self._execute_sql(
                    """
                    INSERT INTO statistics (stat_name, stat_value)
                    VALUES ('api_keys_deleted_inactive_360_days', ?)
                    ON CONFLICT(stat_name) DO UPDATE SET
                        stat_value = stat_value + ?
                    """,
                    (deleted_count, deleted_count),
                )

            if logger:
                logger.info(f"API key cleanup complete: deleted {deleted_count} inactive keys")

            # Update last run time
            self._execute_sql(
                """
                INSERT INTO cleanup_tasks (task_name, last_run)
                VALUES (?, ?)
                ON CONFLICT(task_name) DO UPDATE SET last_run = ?
                """,
                ("api_key_cleanup", int(time.time()), int(time.time())),
            )

        except Exception as e:
            if logger:
                logger.error(f"Error during API key cleanup: {e}")

    def start_all_tasks(self) -> None:
        """
        Start all registered periodic tasks in separate daemon threads.
        Each task runs independently on its own schedule.
        This method is idempotent - calling it multiple times has no effect.
        """
        if self.tasks_started:
            if self.logger:
                self.logger.warning(
                    "Tasks already started, ignoring duplicate start_all_tasks() call"
                )
            return

        self.tasks_started = True
        if self.logger:
            self.logger.info(f"Starting {len(self.tasks)} periodic task(s)...")

        for task_func, interval, task_name in self.tasks:
            thread = threading.Thread(
                target=self._run_task_loop,
                args=(task_func, interval, task_name),
                daemon=True,
                name=f"PeriodicTask-{task_name}",
            )
            thread.start()
            self.running_threads.append(thread)
            if self.logger:
                self.logger.debug(f"Started thread for task: {task_name}")

        if self.logger:
            self.logger.info(f"All {len(self.tasks)} periodic task(s) started")

    # ============================================================================
    # Private Methods (Internal Use Only)
    # ============================================================================

    def _execute_sql(
        self,
        query: str,
        params: Optional[tuple] = None,
        fetch_one: bool = False,
        fetch_all: bool = False,
    ) -> Optional[dict[str, Any]] | list[dict[str, Any]] | int:
        """
        Execute SQL query using direct SQLite connection (thread-safe).

        This method is used by periodic tasks running in threads to avoid
        "event loop already running" errors with the async database handler.

        Args:
            query: SQL query to execute
            params: Query parameters (optional)
            fetch_one: Return single row as dict
            fetch_all: Return all rows as list of dicts

        Returns:
            - If fetch_one: Single row dict or None
            - If fetch_all: List of row dicts (empty list if no results)
            - Otherwise: rowcount for INSERT/UPDATE/DELETE

        Raises:
            ValueError: If db_path is not set
        """
        if not self.db_path:
            raise ValueError("Database path not set. Cannot execute SQL query.")

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            if fetch_one:
                row = cursor.fetchone()
                return dict(row) if row else None
            elif fetch_all:
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            else:
                conn.commit()
                return cursor.rowcount
        finally:
            cursor.close()
            conn.close()

    def _run_task_loop(self, task_func, interval: int, task_name: str) -> None:
        """
        Internal method to run a task in a loop with specified interval.
        Each task gets its own logger named: log_name.task_name

        Args:
            task_func: The task function to run
            interval: How often to run the task (in seconds)
            task_name: Human-readable name for logging
        """
        # Get the task-specific logger
        task_logger = self.task_loggers[task_name]

        if task_logger:
            task_logger.info(f"Started periodic task '{task_name}' (every {interval}s)")
        while True:
            time.sleep(interval)
            try:
                task_func(task_logger)
            except Exception as e:
                if task_logger:
                    task_logger.error(f"Error in periodic task '{task_name}': {e}")
