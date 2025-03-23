from datetime import datetime
from urllib.parse import quote
import requests
import os

TRUENAS_API_KEY = os.getenv("TRUENAS_API_KEY")


def datetimeformat(value):
    """Format timestamp to a readable date/time."""
    try:
        if value:
            return datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')
        else:
            return "N/A"
    except (ValueError, TypeError):
        return "N/A"


def filesizeformat(value):
    """Convert file size from bytes to a human-readable format (MB, KB, etc.)."""
    try:
        size = int(value)
        if size < 1024:
            return f"{size} B"
        elif size < 1024 ** 2:
            return f"{size / 1024:.2f} KB"
        elif size < 1024 ** 3:
            return f"{size / (1024 ** 2):.2f} MB"
        else:
            return f"{size / (1024 ** 3):.2f} GB"
    except (ValueError, TypeError):
        return "N/A"


def filename_without_extension(value):
    """Extract the file name without the extension."""
    try:
        return os.path.splitext(value)[0]
    except Exception:
        return value


def filetype(value):
    """Extract the file type (extension) from the file name in uppercase."""
    try:
        return os.path.splitext(value)[1][1:].upper() or "UNKNOWN"  # Convert extension to uppercase
    except Exception:
        return "UNKNOWN"


