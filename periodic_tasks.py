"""
Periodic background tasks for the GitHub Stars Webhook Limiter.
These tasks run on a schedule to maintain database health.

Usage:
    from periodic_tasks import PeriodicTaskManager
    from CustomModules.DatabaseHandler import DatabaseHandler

    db_handler = DatabaseHandler("GitHub_Events_Limiter/data.db", logger)
    task_manager = PeriodicTaskManager(
        db_handler=db_handler,
        log_manager=log_manager
    )
    task_manager.start_all_tasks()
"""

import threading
import time

from CustomModules.DatabaseHandler import DatabaseHandler
from CustomModules.LogHandler import LogManager


class PeriodicTaskManager:
    """
    Manages periodic background tasks with configurable intervals.

    To add a new task:
    1. Create a method for your task logic
    2. Add it to the tasks list in __init__ with its interval
    3. The task will automatically run when start_all_tasks() is called
    """

    def __init__(
        self, db_handler: DatabaseHandler, log_manager: LogManager, log_name: str = "periodic_tasks"
    ):
        """
        Initialize the periodic task manager.

        Args:
            db_handler: DatabaseHandler instance for database operations
            log_manager: LogManager instance for creating logger
            log_name: Name for the logger (default: "periodic_tasks")
        """
        self.db_handler = db_handler
        self.log_manager = log_manager
        self.log_name = log_name
        self.logger = log_manager.get_logger(log_name)
        self.running_threads = []
        self.task_loggers = {}  # Store loggers for each task
        self.tasks_started = False  # Flag to prevent starting tasks multiple times

        # Register all tasks here - they will automatically start when start_all_tasks() is called
        # Format: self.register_task(method, interval_seconds, "Task Name")
        self.tasks = []
        self.register_task(self.cleanup_expired_rate_limits, 60, "Rate Limit Cleanup")
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
        Remove rate limit tracking entries older than 1 hour.
        This resets rate limits for API keys after the time window has passed.

        Args:
            logger: Logger instance for this task
        """
        try:
            # Calculate the cutoff time (1 hour ago)
            one_hour_ago = int(time.time()) - 3600

            # Delete entries where first request was more than 1 hour ago
            # DatabaseHandler is now SyncDatabaseHandler which handles async internally
            result = self.db_handler.execute(
                """
                DELETE FROM api_rate_limit_tracking
                WHERE first_request_time < ?
                """,
                (one_hour_ago,),
                commit=True,
                fetch=False,  # Get rowcount for DELETE
            )

            # result should be the rowcount (int) when fetch=False
            deleted_count = result if isinstance(result, int) else 0
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} expired rate limit entries")
            else:
                logger.debug("No expired rate limit entries to clean up")

        except Exception as e:
            logger.error(f"Error during rate limit cleanup: {e}")

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

        task_logger.info(f"Started periodic task '{task_name}' (every {interval}s)")
        while True:
            time.sleep(interval)
            try:
                task_func(task_logger)
            except Exception as e:
                task_logger.error(f"Error in periodic task '{task_name}': {e}")

    def start_all_tasks(self) -> None:
        """
        Start all registered periodic tasks in separate daemon threads.
        Each task runs independently on its own schedule.
        This method is idempotent - calling it multiple times has no effect.
        """
        if self.tasks_started:
            self.logger.warning("Tasks already started, ignoring duplicate start_all_tasks() call")
            return

        self.tasks_started = True
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
            self.logger.debug(f"Started thread for task: {task_name}")

        self.logger.info(f"All {len(self.tasks)} periodic task(s) started")
