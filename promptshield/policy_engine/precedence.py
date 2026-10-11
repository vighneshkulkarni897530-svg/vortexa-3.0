from typing import Dict

# Strict deterministic precedence hierarchy:
# BLOCK > ESCALATE > SANITIZE > ALLOW
ACTION_PRECEDENCE: Dict[str, int] = {
    "BLOCK": 40,
    "ESCALATE": 30,
    "SANITIZE": 20,
    "ALLOW": 10,
}

SEVERITY_PRECEDENCE: Dict[str, int] = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 20,
    "LOW": 10,
    "BENIGN": 0,
}


def get_action_rank(action: str) -> int:
    return ACTION_PRECEDENCE.get(action.upper(), 0)


def get_severity_rank(severity: str) -> int:
    return SEVERITY_PRECEDENCE.get(severity.upper(), 0)


def resolve_action_precedence(action_a: str, action_b: str) -> str:
    """
    Returns the higher-precedence action between two choices.
    Guarantee: A BLOCK will never be overridden by SANITIZE, ESCALATE, or ALLOW.
    An ESCALATE will never be overridden by SANITIZE or ALLOW.
    """
    rank_a = get_action_rank(action_a)
    rank_b = get_action_rank(action_b)
    return action_a if rank_a >= rank_b else action_b


def resolve_highest_severity(severities: list[str]) -> str:
    """Return the maximum severity level from a collection."""
    if not severities:
        return "BENIGN"
    highest = "BENIGN"
    highest_rank = -1
    for s in severities:
        r = get_severity_rank(s)
        if r > highest_rank:
            highest_rank = r
            highest = s.upper()
    return highest
