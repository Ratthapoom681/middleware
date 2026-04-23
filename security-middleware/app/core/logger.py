"""
Structured JSON logger for the middleware.
"""

import logging
import sys
import os
from app.config import settings

# Ensure log directory exists
os.makedirs(os.path.dirname(settings.LOG_FILE), exist_ok=True)

logger = logging.getLogger("middleware")
logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

# Format
fmt = logging.Formatter(
    "[%(asctime)s] %(levelname)-8s %(name)s :: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Console handler
console = logging.StreamHandler(sys.stdout)
console.setFormatter(fmt)
logger.addHandler(console)

# File handler
file_h = logging.FileHandler(settings.LOG_FILE, encoding="utf-8")
file_h.setFormatter(fmt)
logger.addHandler(file_h)
