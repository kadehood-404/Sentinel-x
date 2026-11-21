from .rules import CorrelationRule

class PlaceholderRule(CorrelationRule):
    def match(self, events):
        return False
