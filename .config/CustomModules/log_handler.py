"""
Log Handler Module

Provides logging management utilities.
"""

import logging
import os
from logging.handlers import RotatingFileHandler


class LogManager:
    """
    Manages application logging configuration.
    """

    def __init__(self, log_folder: str, app_name: str, log_level: str = "INFO"):
        """
        Initialize the log manager.

        Args:
            log_folder: Directory to store log files
            app_name: Application name for the logger
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.app_name = app_name
        self.log_folder = log_folder
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.logger = None

    def setup(self) -> logging.Logger:
        """
        Set up and configure the logger.

        Returns:
            Configured logger instance
        """
        # Create log folder if it doesn't exist
        os.makedirs(self.log_folder, exist_ok=True)

        # Create logger
        logger = logging.getLogger(self.app_name)
        logger.setLevel(self.log_level)

        # Remove existing handlers to avoid duplicates
        logger.handlers.clear()

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.log_level)
        console_formatter = logging.Formatter(
            "[%(asctime)s] [PID:%(process)-8d] [%(levelname)-8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # File handler with rotation
        log_file = os.path.join(self.log_folder, f"{self.app_name}.log")
        file_handler = RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5  # 10 MB
        )
        file_handler.setLevel(self.log_level)
        file_formatter = logging.Formatter(
            "[%(asctime)s] [PID:%(process)-8d] [%(levelname)-8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        self.logger = logger
        return logger

    def get_logger(self, name: str | None = None) -> logging.Logger:
        """
        Get the configured logger instance or a child logger.

        Args:
            name: Optional name for a child logger

        Returns:
            Logger instance or child logger
        """
        if self.logger is None:
            self.setup()

        assert self.logger is not None, "Logger should be initialized"

        if name and name != self.app_name:
            return self.logger.getChild(name)
        return self.logger
