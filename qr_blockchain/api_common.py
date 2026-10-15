from __future__ import annotations


class RequestBodyTooLarge(ValueError):
    """Raised when an inbound JSON body exceeds the configured byte limit."""
