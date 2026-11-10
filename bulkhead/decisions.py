"""The decision lattice deny < ask < allow (paper, Sec. 3.2)."""
from enum import IntEnum


class Decision(IntEnum):
    DENY = 0
    ASK = 1
    ALLOW = 2

    @classmethod
    def parse(cls, value):
        if isinstance(value, Decision):
            return value
        if isinstance(value, bool):
            return cls.ALLOW if value else cls.DENY
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            raise ValueError(f"not a decision: {value!r}") from None

    def __str__(self):
        return self.name.lower()


def meet(decisions):
    """Greatest lower bound; deny for an empty set."""
    return min(decisions, default=Decision.DENY)


def join(decisions):
    """Least upper bound; deny for an empty set."""
    return max(decisions, default=Decision.DENY)
