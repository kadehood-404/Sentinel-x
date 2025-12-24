from uuid import uuid4
from datetime import datetime

class Incident:
    def __init__(self, events, severity="low", confidence=0.0, description=""):
        self.incident_id = str(uuid4())
        self.created_at = datetime.utcnow().isoformat()
        self.events = events
        self.severity = severity
        self.confidence = confidence
        self.description = description
        self.status = "open"

    def to_dict(self):
        return {
            "incident_id": self.incident_id,
            "created_at": self.created_at,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "status": self.status,
            "event_count": len(self.events),
            "events": self.events
        }
