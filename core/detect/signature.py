from collections import defaultdict
import time

class SignatureEngine:
    def __init__(self):
        self.events = defaultdict(list)

    def process(self, event):
        key = event["source"]["ip"]
        now = time.time()
        self.events[key].append(now)
        self.events[key] = [t for t in self.events[key] if now - t < 60]

        if len(self.events[key]) > 50:
            event["detection"]["method"] = "signature"
            event["severity"] = "medium"
            return event

        return None
