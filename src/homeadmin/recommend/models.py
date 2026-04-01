"""Typed recommendation domain models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Recommendation:
    """Persistable recommendation record."""

    id: str
    category: str
    title: str
    rationale: str
    impact_score: float
    risk_score: float
    effort_score: float
    confidence: float
    priority_rank: int


@dataclass(frozen=True, slots=True)
class RecommendationSourceReferences:
    """Source record references supporting a recommendation."""

    run_id: int
    discrepancy_ids: tuple[int, ...]
    asset_uids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RecommendationEvidenceLink:
    """Normalized recommendation evidence link row."""

    recommendation_id: int
    run_id: int
    discrepancy_id: int | None
    asset_id: int | None
