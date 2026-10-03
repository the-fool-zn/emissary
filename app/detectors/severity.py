"""Explainable severity scoring: every point added is recorded with a reason,
so the analyst (and later the LLM) can see exactly why an alert got its level."""


def to_level(score: int) -> str:
    if score >= 80:
        return "P1"
    if score >= 60:
        return "P2"
    if score >= 35:
        return "P3"
    return "P4"


class Scorer:
    def __init__(self, base: int, why: str):
        self.score = base
        self.reasons = [f"base {base}: {why}"]

    def add(self, points: int, why: str):
        self.score += points
        sign = "+" if points >= 0 else ""
        self.reasons.append(f"{sign}{points}: {why}")

    @property
    def level(self) -> str:
        return to_level(self.score)
