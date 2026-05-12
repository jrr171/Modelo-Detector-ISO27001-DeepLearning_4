"""
Event Classifier
Maps normalised LogEntry objects to ISO 27001 control domains and
marks each event as a "positive indicator" (control active) or a
"risk event" (problem detected).
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import defaultdict

from analyzer.log_parser import LogEntry
from rules.iso27001_controls import ISO27001_DOMAINS, ControlDomain

logger = logging.getLogger(__name__)


@dataclass
class ClassifiedEvent:
    entry: LogEntry
    domain_id: str          # key into ISO27001_DOMAINS
    is_risk: bool           # True → problem, False → positive indicator
    matched_pattern: str


@dataclass
class DomainStats:
    domain_id: str
    domain_name: str
    clause: str
    total_events: int = 0
    indicator_events: int = 0   # evidence that the control EXISTS
    risk_events: int = 0        # evidence of a PROBLEM
    critical_events: int = 0    # level == CRITICAL
    error_events: int = 0       # level == ERROR
    warning_events: int = 0
    unique_ips: set = field(default_factory=set)
    unique_users: set = field(default_factory=set)
    events: List[ClassifiedEvent] = field(default_factory=list)

    @property
    def risk_rate(self) -> float:
        if self.total_events == 0:
            return 0.0
        return self.risk_events / self.total_events

    @property
    def indicator_rate(self) -> float:
        if self.total_events == 0:
            return 0.0
        return self.indicator_events / self.total_events


class EventClassifier:
    """
    Classifies each LogEntry against every ISO 27001 domain and returns
    aggregated per-domain statistics.
    """

    def __init__(self):
        # Pre-compile regexes for speed
        self._indicator_re: Dict[str, List[re.Pattern]] = {}
        self._risk_re: Dict[str, List[re.Pattern]] = {}

        for domain_key, domain in ISO27001_DOMAINS.items():
            self._indicator_re[domain_key] = [
                re.compile(p, re.IGNORECASE) for p in domain.indicators
            ]
            self._risk_re[domain_key] = [
                re.compile(p, re.IGNORECASE) for p in domain.risk_patterns
            ]

    def classify(self, entries: List[LogEntry]) -> Dict[str, DomainStats]:
        """
        Process all entries and return a dict of DomainStats keyed by domain_key.
        """
        stats: Dict[str, DomainStats] = {
            key: DomainStats(
                domain_id=domain.id,
                domain_name=domain.name,
                clause=domain.clause,
            )
            for key, domain in ISO27001_DOMAINS.items()
        }

        # Global stats
        self.total_entries = len(entries)
        self.unclassified = 0

        for entry in entries:
            matched = False
            for domain_key, domain in ISO27001_DOMAINS.items():
                ds = stats[domain_key]

                is_indicator = any(
                    p.search(entry.message) for p in self._indicator_re[domain_key]
                )
                is_risk = any(
                    p.search(entry.message) for p in self._risk_re[domain_key]
                )

                if is_indicator or is_risk:
                    matched = True
                    ds.total_events += 1

                    if entry.source_ip:
                        ds.unique_ips.add(entry.source_ip)
                    if entry.user:
                        ds.unique_users.add(entry.user)

                    if entry.level == "CRITICAL":
                        ds.critical_events += 1
                    elif entry.level == "ERROR":
                        ds.error_events += 1
                    elif entry.level == "WARNING":
                        ds.warning_events += 1

                    if is_risk:
                        ds.risk_events += 1
                        pattern_label = self._get_matched_pattern(
                            entry.message, self._risk_re[domain_key]
                        )
                        ds.events.append(ClassifiedEvent(
                            entry=entry,
                            domain_id=domain_key,
                            is_risk=True,
                            matched_pattern=pattern_label,
                        ))
                    if is_indicator:
                        ds.indicator_events += 1

            if not matched:
                self.unclassified += 1

        return stats

    @staticmethod
    def _get_matched_pattern(text: str, patterns: List[re.Pattern]) -> str:
        for p in patterns:
            m = p.search(text)
            if m:
                return m.group(0)[:50]
        return ""

    def get_top_risks(
        self,
        stats: Dict[str, DomainStats],
        domain_key: str,
        n: int = 5,
    ) -> List[ClassifiedEvent]:
        """Return the n most recent risk events for a domain."""
        domain_risks = [e for e in stats[domain_key].events if e.is_risk]
        return domain_risks[-n:]

    def get_suspicious_ips(
        self,
        stats: Dict[str, DomainStats],
        threshold: int = 5,
    ) -> Dict[str, int]:
        """
        Return IPs that appear in risk events above threshold across all domains.
        """
        ip_counts: Dict[str, int] = defaultdict(int)
        for ds in stats.values():
            for evt in ds.events:
                if evt.is_risk and evt.entry.source_ip:
                    ip_counts[evt.entry.source_ip] += 1
        return {ip: c for ip, c in ip_counts.items() if c >= threshold}
