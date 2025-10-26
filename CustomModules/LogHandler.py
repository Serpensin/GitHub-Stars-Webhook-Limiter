import logging
import logging.handlers
import os
import threading
from colorama import Fore, Style, init


class LogManager:
    """
    Manages the creation of loggers with both file and console handlers.

    Attributes:
        log_folder (str): The folder where log files will be stored.
        app_folder_name (str): The name of the application, used for naming the log file.
        log_level (int): The logging level (e.g., logging.INFO).
    """
    def __init__(self, log_folder, app_folder_name, log_level='INFO'):
        """
        Initializes the LogManager with the specified log folder, application folder name, and log level.

        Args:
            log_folder (str): The folder to store log files.
            app_folder_name (str): The name of the application.
            log_level (str): The log level as a string (e.g., 'INFO', 'DEBUG').
        """
        init()  # Initialize colorama for colored console output.
        self.log_folder = log_folder
        self.app_folder_name = app_folder_name
        self.log_level = self._get_log_level(log_level)
        self._lock = threading.Lock()  # Thread-safety lock for handler operations
    
    def _get_log_level(self, log_level_str) -> int:
        """
        Converts a log level string to the corresponding logging level.

        Args:
            log_level_str (str): The log level as a string (e.g., 'INFO', 'DEBUG').

        Returns:
            int: The logging level.

        Raises:
            ValueError: If the log level string is invalid.
        """
        level = getattr(logging, log_level_str.upper(), None)
        if isinstance(level, int):
            return level
        else:
            raise ValueError(f"Invalid log level: {log_level_str}")
    
    def get_logger(self, logger_name) -> logging.Logger:
        """
        Creates and configures a logger with file and console handlers.

        Args:
            logger_name (str): The name of the logger.

        Returns:
            logging.Logger: The configured logger.
        """
        # Create the logger
        logger = logging.getLogger(logger_name)
        logger.setLevel(self.log_level)
        
        # Prevent duplicate handlers if logger already exists
        if logger.handlers:
            return logger
        
        # Create a file handler that rotates logs at midnight
        file_handler = logging.handlers.TimedRotatingFileHandler(
            filename=os.path.join(self.log_folder, f'{self.app_folder_name}.log'),
            when='midnight',
            encoding='utf-8',
            backupCount=27,
            delay=True
        )
        
        # Customize rotation naming: NAME.DATUM.log instead of NAME.log.DATUM
        file_handler.namer = lambda name: name.replace('.log', '') + '.log'
        
        # Make the file handler thread-safe by adding a lock
        original_emit = file_handler.emit
        def thread_safe_emit(record):
            with self._lock:
                original_emit(record)
        file_handler.emit = thread_safe_emit
        
        # Create a console handler with color support
        console_handler = logging.StreamHandler()
        
        # Create a formatter for the file handler
        dt_fmt = '%Y-%m-%d %H:%M:%S'
        file_formatter = logging.Formatter('[{asctime}] [PID:{process:<6}] [{levelname:<8}] {name}: {message}', dt_fmt, style='{')
        file_handler.setFormatter(file_formatter)
        
        # Create a formatter for the console handler with color
        color_formatter = _ColoredFormatter('[{asctime}] [PID:{process:<6}] [{levelname:<8}] {name}: {message}', dt_fmt, style='{')
        console_handler.setFormatter(color_formatter)
        
        # Add the handlers to the logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        # Prevent propagation to parent loggers to avoid duplicate log messages
        logger.propagate = False
        
        return logger


class _ColoredFormatter(logging.Formatter):
    """
    A logging formatter that adds color to log messages based on their severity level.

    Attributes:
        COLOR_MAP (dict): A mapping of log levels to colorama color codes.
    """
    COLOR_MAP = {
        'DEBUG': Fore.BLUE,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA,
    }

    def format(self, record) -> str:
        """
        Formats the log record with color based on the log level.

        Args:
            record (logging.LogRecord): The log record to format.

        Returns:
            str: The formatted log message with color.
        """
        log_color = self.COLOR_MAP.get(record.levelname, Fore.WHITE)
        log_msg = super().format(record)
        return f"{log_color}{log_msg}{Style.RESET_ALL}"