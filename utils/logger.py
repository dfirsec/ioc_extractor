"""Logging configuration for the project."""
import logging

from rich.logging import RichHandler


class LazyFileHandler(logging.FileHandler):
    """A file handler that is initialized only when an error is logged."""

    def __init__(self, *args, **kwargs):
        """Initialization that stores the arguments and keyword arguments passed to it."""
        self._args = args
        self._kwargs = kwargs
        self._initialized = False

    def _initialize(self):
        if not self._initialized:
            super().__init__(*self._args, **self._kwargs)  # noqa: WPS613
            self._initialized = True

    def emit(self, record: logging.LogRecord) -> None:
        """
        Emits a log record if its level is equal to or greater than ERROR.

        Args:
            record (logging.LogRecord):
              Contains all the information about a log message.
        """
        if record.levelno >= logging.ERROR:
            self._initialize()
            super().emit(record)


def logger() -> logging.Logger:
    """
    Sets up a logger with a file handler for errors, and returns the logger object.

    Returns:
        A logger object with a configured logging level, format, and handlers, including a file
        handler for logging errors to a file named "errors.log".
    """
    logging.basicConfig(level="INFO", format="%(asctime)s %(message)s", handlers=[RichHandler()])

    log = logging.getLogger("rich")
    handler = LazyFileHandler("errors.log", mode="a")
    handler.setLevel(logging.ERROR)
    log.addHandler(handler)

    return log
