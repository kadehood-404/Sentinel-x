import time
from collections import defaultdict
from .models import Incident

class CorrelationEngine:
    def __init__(self):
        self.buffers = defaultdict(list)
        self.rules = []

    def register_rule(self, rule):
        self.rules.append(rule)

    def ingest_event(self, event):
        """
        Store events keyed by source (IP or hostname)
        """
        key = event["source"].get("ip") or event["source"].get("hostname")
        now = time.time()

        self.buffers[key].append((now, event))
        self._expire_old_events(key, now)

        return self._evaluate(key)

    def _expire_old_events(self, key, now):
        self.buffers[key] = [
            (ts, ev) for ts, ev in self.buffers[key]
            if now - ts < 3600
        ]

    def _evaluate(self, key):
        incidents = []

        events = [ev for _, ev in self.buffers[key]]

        for rule in self.rules:
            if rule.match(events):
                incidents.append(
                    Incident(
                        events=events,
                        severity="medium",
                        confidence=0.6,
                        description=f"Correlation rule {rule.rule_id} matched"
                    )
                )

        return incidents
