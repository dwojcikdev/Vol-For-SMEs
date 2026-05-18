"""
Logging utilities for the application.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    format_string: Optional[str] = None
) -> logging.Logger:
    """
    Set up application logging.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for logging
        format_string: Optional custom format string

    Returns:
        Configured logger instance
    """
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Create formatter
    formatter = logging.Formatter(format_string)

    # Get or create logger
    logger = logging.getLogger("vol_for_smes")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        log_file = Path(log_file).expanduser().resolve()
        log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(f"vol_for_smes.{name}")


class LogContext:
    """
    Context manager for temporary logging configuration.
    """

    def __init__(self, level: str = "DEBUG", log_file: Optional[Path] = None):
        self.level = level
        self.log_file = log_file
        self.original_level = None
        self.original_handlers = None

    def __enter__(self):
        logger = logging.getLogger("vol_for_smes")
        self.original_level = logger.level
        self.original_handlers = logger.handlers[:]

        # Temporarily change level
        logger.setLevel(getattr(logging, self.level.upper(), logging.DEBUG))

        # Add file handler if specified
        if self.log_file:
            log_file = Path(self.log_file).expanduser().resolve()
            log_file.parent.mkdir(parents=True, exist_ok=True)

            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger = logging.getLogger("vol_for_smes")
        logger.setLevel(self.original_level)

        # Restore original handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        for handler in self.original_handlers:
            logger.addHandler(handler)