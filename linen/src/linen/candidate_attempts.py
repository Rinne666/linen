"""Shared identity rules for audit candidate-attempt budgets."""


def is_candidate_attempt(fact_type: str | None, semantic_type: str | None) -> bool:
    """Whether a Fact represents an original vulnerability candidate attempt.

    Confirmation creates a promoted finding, which must not consume another
    candidate slot. Other semantic outcomes remain the same attempt and keep
    consuming the slot after rejection, review, or disposition.
    """
    return fact_type == "vulnerability" and semantic_type != "confirmed_finding"
