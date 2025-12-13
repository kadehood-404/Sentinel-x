class EventStore:
    def write(self, event: dict):
        raise NotImplementedError

    def query(self, limit=100):
        raise NotImplementedError
