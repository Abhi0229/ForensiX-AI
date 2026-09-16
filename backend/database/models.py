"""Data models used by the database layer."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Event:
    """A forensic event recorded by the application."""

    event_type: str
    source: str
    timestamp: str
    details: str = ""