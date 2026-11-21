import json

class FileEventStore:
    def __init__(self, path="storage/events.log"):
        self.path = path

    def write(self, event):
        with open(self.path, "a") as f:
            f.write(json.dumps(event) + "\n")
