"""Usage accounting subsystem (PLAN §13.5, §14, §21; issue #28).

Records every model call as a ``usage_event`` and answers attribution
questions: how many tokens/requests/cost per provider, model, campaign,
agent, task, or time range — with free-tier usage separable from paid usage
in every aggregate.
"""

from usage.ledger import (
    Budget,
    BudgetBreach,
    LedgerQuery,
    UsageLedger,
)

__all__ = ["Budget", "BudgetBreach", "LedgerQuery", "UsageLedger"]
