class CorrelationRule:
    def __init__(self, rule_id, window_seconds, threshold):
        self.rule_id = rule_id
        self.window_seconds = window_seconds
        self.threshold = threshold

    def match(self, events):
        """
        Returns True if correlation conditions are met.
        Override this later.
        """
        return False
