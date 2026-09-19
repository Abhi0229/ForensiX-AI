from dataclasses import dataclass
from datetime import datetime


@dataclass
class Event:
    timestamp: datetime
    source: str
    event_type: str
    description: str
    severity: str = "INFO"
    user: str = ""
    device: str = ""
    file_path: str = ""
    metadata: str = ""
    