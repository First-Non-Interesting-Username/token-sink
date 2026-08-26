"""Model-family diversity enforcement for reviewer panels (PLAN §7.2, §10.5;
issue #122).

Four "independent" PoC reviewers that all resolve to the same underlying
model family are not independent. When composing a multi-reviewer panel,
this module enforces a cap of N reviewers per model family (default 1):

- ``family_of`` derives the model family from catalog metadata. Unknown
  families are treated as their own value and flagged (``unknown=True``),
  never silently grouped with a guessed lineage.
- :meth:`DiversityGate.compose_panel` selects reviewers under the cap in
  two passes so distinct families always win over input order; if the pool
  still cannot fill the panel within the cap it falls back to same-family
  candidates WITH an explicit ``fallback_warning`` per pick — degraded
  independence is visible, never silent.
- Every rejection/fallback/unknown-family outcome emits a
  :class:`DiversityEvent` for the UI / metrics / audit trail, mirroring
  the free-only gate (#66) shape.
- The cap is overridable per campaign via config (§16).

Interaction with free-only mode (#66): pass already-filtered candidates in
(the caller runs FreeOnlyGate first); when diversity cannot be achieved
within that filtered set the shortfall is surfaced as explicit warnings,
so operators see when free-only + diversity are jointly unsatisfiable.
"""

from __future__ import annotations

import time
import uuid
from collections import Counter
from dataclasses import dataclass
from typing import Any


def family_of(
    provider: str,
    model: str,
    families: dict[str, str] | None = None,
) -> tuple[str, bool]:
    """Return ``(family, unknown)`` for a provider/model pair.

    Lookup order: explicit catalog mapping by full id ("provider/model"),
    then by bare model name; anything else resolves to a synthetic family
    keyed by the exact id so it is its own value and flagged unknown.
    """
    families = families or {}
    key = f"{provider}/{model}"
    if key in families:
        return families[key], False
    if model in families:
        return families[model], False
    return key, True


@dataclass(frozen=True)
class DiversityEvent:
    """One diversity-enforcement outcome (UI/metrics/audit payload)."""

    event_id: str
    ts: float
    kind: str  # "violation" | "fallback_warning" | "unknown_family" | "composed"
    detail: str
    campaign_id: str | None = None


@dataclass(frozen=True)
class PanelMember:
    """A selected reviewer slot."""

    provider: str
    model: str
    router_id: str
    family: str
    family_unknown: bool


class DiversityGate:
    """Compose reviewer panels honoring a max-per-model-family cap."""

    def __init__(
        self,
        families: dict[str, str] | None = None,
        default_cap: int = 1,
        campaign_caps: dict[str, int] | None = None,
        clock: Any = time.time,
    ) -> None:
        # families: {"provider/model": "family"} or {"model": "family"}
        self.families = dict(families or {})
        self.default_cap = default_cap
        self.campaign_caps = dict(campaign_caps or {})
        self._clock = clock
        self.events: list[DiversityEvent] = []

    # -- internals ---------------------------------------------------------

    def _cap(self, campaign_id: str | None) -> int:
        """Per-campaign override wins over the global default (§16)."""
        if campaign_id and campaign_id in self.campaign_caps:
            return self.campaign_caps[campaign_id]
        return self.default_cap

    def _record(self, kind: str, detail: str, campaign_id: str | None) -> DiversityEvent:
        ev = DiversityEvent(
            event_id=uuid.uuid4().hex,
            ts=self._clock(),
            kind=kind,
            detail=detail,
            campaign_id=campaign_id,
        )
        self.events.append(ev)
        return ev

    # -- public API --------------------------------------------------------

    def compose_panel(
        self,
        candidates: list[Any],
        panel_size: int,
        campaign_id: str | None = None,
    ) -> tuple[list[PanelMember], list[DiversityEvent]]:
        """Select up to ``panel_size`` reviewers from candidate plans.

        Candidates must already be free-only filtered (#66) when free-only
        mode applies — this gate does not re-check cost status.

        Pass 1 admits every candidate whose family has headroom under the
        cap (input order breaks ties). Pass 2 fires only when the pool
        could not fill the panel within the cap: capped-out candidates are
        then admitted one-by-one, each emitting an explicit fallback
        warning. Cap-exceeded candidates left unselected produce
        ``violation`` events; selected models with no catalog family
        produce ``unknown_family`` flags.
        """
        cap = self._cap(campaign_id)
        if cap < 1:
            raise ValueError("per-family cap must be >= 1")
        before = len(self.events)

        family_counts: Counter[str] = Counter()
        within_cap: list[PanelMember] = []
        exceeded: list[PanelMember] = []
        unknown_selected = 0

        for cand_ in candidates or []:
            provider = str(getattr(cand_, "provider", ""))
            model = str(getattr(cand_, "model", ""))
            router_id = str(getattr(cand_, "router_id", ""))
            fam, unk = family_of(provider, model, self.families)
            if family_counts[fam] < cap:
                family_counts[fam] += 1
                within_cap.append(PanelMember(provider, model, router_id, fam, unk))
            else:
                exceeded.append(PanelMember(provider, model, router_id, fam, unk))

        # Pass 1: distinct families first.
        panel = within_cap[:panel_size]
        # Anything within-cap that did not fit the panel size was simply
        # surplus capacity, not a violation — no event needed for it.
        unknown_selected = sum(1 for m in panel if m.family_unknown)
        for _ in range(unknown_selected):
            self._record(
                "unknown_family",
                (
                    "selected model has no known family in the catalog; it is "
                    "treated as its own family and flagged rather than grouped"
                ),
                campaign_id,
            )

        # Pass 2: fill remaining slots from cap-exceeded candidates, loudly.
        filled_by_fallback = 0
        idx = 0
        while len(panel) < panel_size and idx < len(exceeded):
            member = exceeded[idx]
            idx += 1
            panel.append(member)
            filled_by_fallback += 1
            self._record(
                "fallback_warning",
                (
                    f"panel independence degraded: added {member.provider}/"
                    f"{member.model} (family '{member.family}' already at the "
                    f"{cap}-reviewer cap); catalog lacks enough distinct families"
                ),
                campaign_id,
            )

        # Cap-exceeded candidates that were NOT needed are policy violations.
        for member in exceeded[idx:]:
            self._record(
                "violation",
                (
                    f"rejected {member.provider}/{member.model}: cap reached — "
                    f"family '{member.family}' already has {cap} reviewer(s) "
                    f"(max {cap} per family)"
                ),
                campaign_id,
            )

        if len(panel) < panel_size:
            self._record(
                "fallback_warning",
                (
                    f"panel underfilled: only {len(panel)} of {panel_size} "
                    f"reviewers available from the candidate pool"
                ),
                campaign_id,
            )
        elif filled_by_fallback == 0:
            self._record(
                "composed",
                (f"panel of {len(panel)} composed within {cap}-per-family cap"),
                campaign_id,
            )

        return panel, list(self.events[before:])
