"""
FileSense — Logging Module
===========================
Provides a configured logger. No silent failures.
"""

import logging
import os

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

LEVEL_COLORS = {
    "DEBUG":    BLUE,
    "INFO":     GREEN,
    "WARNING":  YELLOW,
    "ERROR":    RED,
    "CRITICAL": RED + BOLD,
}


class ColorFormatter(logging.Formatter):
    def format(self, record):
        level_color = LEVEL_COLORS.get(record.levelname, RESET)
        record.levelname_colored = f"{level_color}{record.levelname:<8}{RESET}"
        return super().format(record)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"filesense.{name}")
    
    if logger.handlers:
        return logger

    level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)
    logger.setLevel(level)

    handler = logging.StreamHandler()
    handler.setLevel(level)

    formatter = ColorFormatter(
        f"{CYAN}%(asctime)s{RESET} "
        f"{BOLD}%(name)s{RESET} "
        f"%(levelname_colored)s "
        f"%(message)s",
        datefmt="%H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
