"""
Maturity Scorer
Converts per-domain statistics into ISO 27001 maturity scores (0–100)
and determines the overall maturity level (0–5) of the organisation.

Scoring algorithm
-----------------
Each domain is scored independently, then a weighted average is taken.

Domain score (0–100) is built from four components:

  1. Logging presence (0–30 pts)
     Does the domain have any logged events?  The more events, the
     higher the confidence that monitoring is active.

  2. Control effectiveness (0–40 pts)
     Based on the risk-event ratio.  A low ratio means controls are
     working; a high ratio signals problems.

  3. Severity bonus/penalty (±15 pts)
     CRITICAL / ERROR events reduce the score; predominance of INFO
     events gives a small bonus.

  4. Coverage bonus (0–15 pts)
     Number of unique IPs / users observed indicates broad coverage.

Final domain score is clamped to [0, 100].

Overall maturity score = Σ (domain_score × domain_weight)

Maturity level thresholds (from COBIT / thesis):
  0 → 0 %
  1 → 1–20 %
  2 → 21–40 %
  3 → 41–60 %
  4 → 61–80 %
  5 → 81–100 %
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from analyzer.event_classifier import DomainStats
from rules.iso27001_controls import (
    ISO27001_DOMAINS,
    MATURITY_LEVELS,
    THRESHOLDS,
    MIN_EVENTS_FOR_LOGGING,
    get_maturity_level,
)

logger = logging.getLogger(__name__)


@dataclass
class DomainScore:
    domain_key: str
    domain_name: str
    clause: str
    weight: float
    raw_score: float            # 0–100
    weighted_contribution: float
    level: int                  # 0–5
    level_name: str
    breakdown: Dict[str, float] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


@dataclass
class MaturityResult:
    overall_score: float                    # 0–100
    overall_level: int                      # 0–5
    overall_level_name: str
    domain_scores: Dict[str, DomainScore]
    total_events: int
    total_risk_events: int
    total_domains_active: int
    percentage_per_level: Dict[int, float]  # % of domains at each level
    recommendations: List[str]
    critical_findings: List[str]


class MaturityScorer:
    """Compute ISO 27001 maturity scores from classified domain statistics."""

    # ── public API ──────────────────────────────────────────────────────────

    def score(self, stats: Dict[str, DomainStats]) -> MaturityResult:
        domain_scores: Dict[str, DomainScore] = {}
        total_events = 0
        total_risk = 0
        active_domains = 0

        for key, ds in stats.items():
            total_events += ds.total_events
            total_risk += ds.risk_events
            if ds.total_events >= MIN_EVENTS_FOR_LOGGING:
                active_domains += 1

            raw, breakdown, notes = self._score_domain(ds)
            weight = ISO27001_DOMAINS[key].weight
            level = get_maturity_level(raw)

            domain_scores[key] = DomainScore(
                domain_key=key,
                domain_name=ds.domain_name,
                clause=ds.clause,
                weight=weight,
                raw_score=raw,
                weighted_contribution=raw * weight,
                level=level,
                level_name=MATURITY_LEVELS[level]["name"],
                breakdown=breakdown,
                notes=notes,
            )

        # ── Overall weighted score ──────────────────────────────────────────
        overall = sum(ds.weighted_contribution for ds in domain_scores.values())
        # Weights sum to 1 by definition, but clamp just in case
        overall = max(0.0, min(100.0, overall))
        overall_level = get_maturity_level(overall)

        # ── Distribution ────────────────────────────────────────────────────
        level_counts: Dict[int, int] = {i: 0 for i in range(6)}
        for ds in domain_scores.values():
            level_counts[ds.level] += 1
        n = len(domain_scores) or 1
        pct_per_level = {lvl: (cnt / n) * 100 for lvl, cnt in level_counts.items()}

        # ── Recommendations & critical findings ─────────────────────────────
        recommendations = self._build_recommendations(domain_scores, overall_level)
        critical_findings = self._find_critical_issues(domain_scores, stats)

        return MaturityResult(
            overall_score=round(overall, 2),
            overall_level=overall_level,
            overall_level_name=MATURITY_LEVELS[overall_level]["name"],
            domain_scores=domain_scores,
            total_events=total_events,
            total_risk_events=total_risk,
            total_domains_active=active_domains,
            percentage_per_level=pct_per_level,
            recommendations=recommendations,
            critical_findings=critical_findings,
        )

    # ── Internal scoring ────────────────────────────────────────────────────

    def _score_domain(
        self, ds: DomainStats
    ) -> Tuple[float, Dict[str, float], List[str]]:
        breakdown: Dict[str, float] = {}
        notes: List[str] = []

        # ── Component 1: Logging presence (0–30) ───────────────────────────
        if ds.total_events == 0:
            presence = 0.0
            notes.append("Sin eventos registrados en este dominio.")
        else:
            # Logarithmic scale: 10 events → ~10 pts, 100 → ~20 pts, 500 → ~30 pts
            presence = min(30.0, 10 * math.log10(ds.total_events + 1))
        breakdown["logging_presence"] = round(presence, 2)

        # ── Component 2: Control effectiveness (0–40) ──────────────────────
        if ds.total_events == 0:
            effectiveness = 0.0
        else:
            rr = ds.risk_rate
            if rr > THRESHOLDS["critical_failure_rate"]:
                effectiveness = 5.0
                notes.append(
                    f"Tasa de riesgo crítica ({rr:.0%}). Controles muy deficientes."
                )
            elif rr > THRESHOLDS["high_failure_rate"]:
                effectiveness = 15.0
                notes.append(
                    f"Tasa de riesgo alta ({rr:.0%}). Controles insuficientes."
                )
            elif rr > THRESHOLDS["medium_failure_rate"]:
                effectiveness = 28.0
            else:
                effectiveness = 40.0
                if rr == 0:
                    notes.append("Sin eventos de riesgo detectados en este dominio.")
        breakdown["control_effectiveness"] = round(effectiveness, 2)

        # ── Component 3: Severity adjustment (±15) ─────────────────────────
        if ds.total_events == 0:
            sev_adj = 0.0
        else:
            critical_rate = ds.critical_events / ds.total_events
            error_rate = ds.error_events / ds.total_events
            sev_adj = 15.0 - (critical_rate * 30 + error_rate * 15)
            sev_adj = max(-15.0, min(15.0, sev_adj))
            if ds.critical_events > 0:
                notes.append(
                    f"{ds.critical_events} eventos CRÍTICOS detectados."
                )
        breakdown["severity_adjustment"] = round(sev_adj, 2)

        # ── Component 4: Coverage bonus (0–15) ─────────────────────────────
        if ds.total_events == 0:
            coverage = 0.0
        else:
            ip_score = min(7.5, len(ds.unique_ips) * 0.5)
            user_score = min(7.5, len(ds.unique_users) * 0.75)
            coverage = ip_score + user_score
        breakdown["coverage_bonus"] = round(coverage, 2)

        # ── Total ───────────────────────────────────────────────────────────
        raw = presence + effectiveness + sev_adj + coverage
        raw = max(0.0, min(100.0, raw))

        return round(raw, 2), breakdown, notes

    # ── Recommendations & findings ──────────────────────────────────────────

    def _build_recommendations(
        self,
        domain_scores: Dict[str, DomainScore],
        overall_level: int,
    ) -> List[str]:
        recs: List[str] = []

        # Global level recommendation
        recs.extend(MATURITY_LEVELS[overall_level]["recommendations"])

        # Worst-performing domains
        worst = sorted(domain_scores.values(), key=lambda d: d.raw_score)[:2]
        for ds in worst:
            if ds.raw_score < 40:
                recs.append(
                    f"Priorizar mejoras en '{ds.domain_name}' ({ds.clause}) "
                    f"— score actual: {ds.raw_score:.1f}/100."
                )

        return recs

    def _find_critical_issues(
        self,
        domain_scores: Dict[str, DomainScore],
        stats: Dict[str, DomainStats],
    ) -> List[str]:
        findings: List[str] = []

        for key, ds_score in domain_scores.items():
            ds = stats[key]
            if ds.critical_events > 0:
                findings.append(
                    f"[{ds_score.clause}] {ds.critical_events} evento(s) CRÍTICO(s) detectado(s)."
                )
            if ds.total_events >= MIN_EVENTS_FOR_LOGGING and ds.risk_rate > 0.30:
                findings.append(
                    f"[{ds_score.clause}] Tasa de fallos > 30% "
                    f"({ds.risk_events}/{ds.total_events} eventos son de riesgo)."
                )
            if ds.total_events == 0:
                findings.append(
                    f"[{ds_score.clause}] Sin eventos registrados — "
                    "dominio sin monitoreo activo."
                )

        return findings
