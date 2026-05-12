"""
Unit tests for the Security Maturity Analyzer.
Run: python -m pytest tests/ -v
"""

import sys
import os
import tempfile
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.log_parser import LogParser, LogEntry
from analyzer.event_classifier import EventClassifier
from analyzer.maturity_scorer import MaturityScorer
from rules.iso27001_controls import get_maturity_level, MATURITY_LEVELS, ISO27001_DOMAINS


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def write_tmp(content: str, suffix: str = ".log") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


# ─────────────────────────────────────────────────────────────────────────────
# 1. Maturity level thresholds
# ─────────────────────────────────────────────────────────────────────────────

class TestMaturityLevels:
    def test_level_zero(self):
        assert get_maturity_level(0) == 0

    def test_level_one_boundaries(self):
        assert get_maturity_level(1)  == 1
        assert get_maturity_level(20) == 1

    def test_level_two_boundaries(self):
        assert get_maturity_level(21) == 2
        assert get_maturity_level(40) == 2

    def test_level_three_boundaries(self):
        assert get_maturity_level(41) == 3
        assert get_maturity_level(60) == 3

    def test_level_four_boundaries(self):
        assert get_maturity_level(61) == 4
        assert get_maturity_level(80) == 4

    def test_level_five_boundaries(self):
        assert get_maturity_level(81)  == 5
        assert get_maturity_level(100) == 5

    def test_all_levels_have_descriptions(self):
        for lvl in range(6):
            assert "name" in MATURITY_LEVELS[lvl]
            assert "description" in MATURITY_LEVELS[lvl]
            assert "recommendations" in MATURITY_LEVELS[lvl]
            assert len(MATURITY_LEVELS[lvl]["recommendations"]) > 0


# ─────────────────────────────────────────────────────────────────────────────
# 2. Log Parser
# ─────────────────────────────────────────────────────────────────────────────

APACHE_LOG = """\
192.168.1.10 - alice [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://ref" "Mozilla/5.0"
10.0.0.22 - - [01/Jan/2024:10:01:00 +0000] "GET /admin HTTP/1.1" 403 512 "-" "curl/7.68.0"
203.0.113.77 - - [01/Jan/2024:10:02:00 +0000] "POST /.env HTTP/1.1" 404 0 "-" "python-requests/2.25.1"
"""

SYSLOG_LOG = """\
Jan  1 10:00:00 srv sshd[1234]: Accepted password for alice from 192.168.1.10 port 45321 ssh2
Jan  1 10:01:00 srv sshd[1235]: Failed password for root from 203.0.113.77 port 59876 ssh2
Jan  1 10:02:00 srv sshd[1236]: Invalid user admin from 45.33.32.156 port 60000
Jan  1 10:03:00 srv kernel[1]: Out of memory: Kill process 999 (python)
"""

WINDOWS_CSV = """\
TimeCreated,Id,LevelDisplayName,Message,UserName,Computer
2024-01-01T10:00:00,4624,Information,An account was successfully logged on. User: alice,alice,WIN-SRV01
2024-01-01T10:01:00,4625,Warning,An account failed to log on. User: bob IP: 10.0.0.22,bob,WIN-SRV01
2024-01-01T10:02:00,5157,Warning,The Windows Filtering Platform blocked a connection from 203.0.113.77,,WIN-SRV01
"""


class TestLogParser:
    def test_parse_apache(self):
        path = write_tmp(APACHE_LOG)
        parser = LogParser()
        entries = parser.parse_path(path)
        assert len(entries) >= 2
        ips = {e.source_ip for e in entries if e.source_ip}
        assert "192.168.1.10" in ips
        os.unlink(path)

    def test_apache_status_levels(self):
        path = write_tmp(APACHE_LOG)
        parser = LogParser()
        entries = parser.parse_path(path)
        levels = {e.level for e in entries}
        assert "WARNING" in levels or "INFO" in levels
        os.unlink(path)

    def test_parse_syslog(self):
        path = write_tmp(SYSLOG_LOG)
        parser = LogParser()
        entries = parser.parse_path(path)
        assert len(entries) >= 3
        os.unlink(path)

    def test_parse_windows_csv(self):
        path = write_tmp(WINDOWS_CSV, suffix=".csv")
        parser = LogParser()
        entries = parser.parse_path(path)
        assert len(entries) >= 2
        os.unlink(path)

    def test_parse_empty_file(self):
        path = write_tmp("")
        parser = LogParser()
        entries = parser.parse_path(path)
        assert entries == []
        os.unlink(path)

    def test_parse_nonexistent_raises(self):
        parser = LogParser()
        with pytest.raises(FileNotFoundError):
            parser.parse_path("/nonexistent/path/file.log")

    def test_stats_populated(self):
        path = write_tmp(SYSLOG_LOG)
        parser = LogParser()
        parser.parse_path(path)
        assert parser.stats["total_lines"] > 0
        assert parser.stats["parsed_ok"] > 0
        os.unlink(path)

    def test_parse_directory(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "a.log").write_text(APACHE_LOG)
            Path(d, "b.log").write_text(SYSLOG_LOG)
            parser = LogParser()
            entries = parser.parse_path(d)
            assert len(entries) >= 5


# ─────────────────────────────────────────────────────────────────────────────
# 3. Event Classifier
# ─────────────────────────────────────────────────────────────────────────────

class TestEventClassifier:
    def _entries_from(self, text: str, suffix=".log"):
        path = write_tmp(text, suffix=suffix)
        entries = LogParser().parse_path(path)
        os.unlink(path)
        return entries

    def test_access_control_detects_failures(self):
        entries = self._entries_from(SYSLOG_LOG)
        stats = EventClassifier().classify(entries)
        ac = stats["access_control"]
        assert ac.risk_events > 0, "Should detect SSH failures"

    def test_access_control_detects_success(self):
        entries = self._entries_from(SYSLOG_LOG)
        stats = EventClassifier().classify(entries)
        ac = stats["access_control"]
        assert ac.indicator_events > 0

    def test_windows_events_classified(self):
        entries = self._entries_from(WINDOWS_CSV, suffix=".csv")
        stats = EventClassifier().classify(entries)
        # Windows Event IDs 4624/4625 map to access_control domain
        ac = stats["access_control"]
        assert ac.total_events > 0, "Windows logon events should be classified"

    def test_all_domains_present_in_output(self):
        entries = self._entries_from(SYSLOG_LOG)
        stats = EventClassifier().classify(entries)
        for key in ISO27001_DOMAINS:
            assert key in stats

    def test_unique_ips_tracked(self):
        entries = self._entries_from(SYSLOG_LOG)
        stats = EventClassifier().classify(entries)
        ac = stats["access_control"]
        assert len(ac.unique_ips) > 0

    def test_critical_events_counted(self):
        entries = self._entries_from(SYSLOG_LOG)
        stats = EventClassifier().classify(entries)
        ops = stats["operations_security"]
        # "Out of memory" is matched as a risk event for operations_security
        assert ops.risk_events >= 1, "Out of memory should be a risk event"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Maturity Scorer
# ─────────────────────────────────────────────────────────────────────────────

class TestMaturityScorer:
    def _result_from(self, text: str, suffix=".log"):
        path = write_tmp(text, suffix=suffix)
        entries = LogParser().parse_path(path)
        os.unlink(path)
        stats = EventClassifier().classify(entries)
        return MaturityScorer().score(stats)

    def test_score_in_range(self):
        result = self._result_from(SYSLOG_LOG)
        assert 0 <= result.overall_score <= 100

    def test_level_in_range(self):
        result = self._result_from(SYSLOG_LOG)
        assert 0 <= result.overall_level <= 5

    def test_domain_scores_present(self):
        result = self._result_from(SYSLOG_LOG)
        for key in ISO27001_DOMAINS:
            assert key in result.domain_scores

    def test_empty_logs_give_zero(self):
        path = write_tmp("")
        entries = LogParser().parse_path(path)
        os.unlink(path)
        stats = EventClassifier().classify(entries)
        result = MaturityScorer().score(stats)
        assert result.overall_score == 0.0
        assert result.overall_level == 0

    def test_many_failures_lower_score(self):
        """A log full of failures should score lower than one with mostly successes."""
        good_log = "\n".join(
            f"Jan  1 10:00:{i:02d} srv sshd[100]: Accepted password for alice from 10.0.0.1 port 22 ssh2"
            for i in range(30)
        )
        bad_log = "\n".join(
            f"Jan  1 10:00:{i:02d} srv sshd[100]: Failed password for root from 1.2.3.4 port 22 ssh2"
            for i in range(30)
        )
        r_good = self._result_from(good_log)
        r_bad  = self._result_from(bad_log)
        assert r_good.overall_score >= r_bad.overall_score

    def test_recommendations_provided(self):
        result = self._result_from(SYSLOG_LOG)
        assert len(result.recommendations) > 0

    def test_critical_findings_when_no_events(self):
        path = write_tmp("")
        entries = LogParser().parse_path(path)
        os.unlink(path)
        stats = EventClassifier().classify(entries)
        result = MaturityScorer().score(stats)
        # Every domain without events should flag a finding
        assert any("Sin eventos" in f for f in result.critical_findings)

    def test_weights_sum_to_one(self):
        total = sum(d.weight for d in ISO27001_DOMAINS.values())
        assert abs(total - 1.0) < 0.001


# ─────────────────────────────────────────────────────────────────────────────
# 5. End-to-end integration
# ─────────────────────────────────────────────────────────────────────────────

class TestEndToEnd:
    def test_full_pipeline_apache(self):
        path = write_tmp(APACHE_LOG)
        parser = LogParser()
        entries = parser.parse_path(path)
        stats = EventClassifier().classify(entries)
        result = MaturityScorer().score(stats)
        os.unlink(path)
        # Level must be valid regardless of event count
        assert result.overall_level in range(6)
        assert 0 <= result.overall_score <= 100

    def test_full_pipeline_mixed_directory(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "access.log").write_text(APACHE_LOG)
            Path(d, "auth.log").write_text(SYSLOG_LOG)
            Path(d, "events.csv").write_text(WINDOWS_CSV)
            entries = LogParser().parse_path(d)
            stats = EventClassifier().classify(entries)
            result = MaturityScorer().score(stats)
            # Parsed entries should exceed the 3 pure domain-classified events
            assert len(entries) >= 8
            assert 0 <= result.overall_score <= 100

    def test_html_report_generated(self, tmp_path):
        from analyzer.report_generator import export_html
        path = write_tmp(SYSLOG_LOG)
        entries = LogParser().parse_path(path)
        stats = EventClassifier().classify(entries)
        result = MaturityScorer().score(stats)
        os.unlink(path)
        html_out = str(tmp_path / "report.html")
        export_html(result, "test.log", html_out)
        content = Path(html_out).read_text()
        assert "Madurez" in content
        assert "ISO" in content

    def test_json_export(self, tmp_path):
        import json
        from analyzer.report_generator import export_json
        path = write_tmp(SYSLOG_LOG)
        entries = LogParser().parse_path(path)
        stats = EventClassifier().classify(entries)
        result = MaturityScorer().score(stats)
        os.unlink(path)
        json_out = str(tmp_path / "result.json")
        export_json(result, json_out)
        data = json.loads(Path(json_out).read_text())
        assert "overall" in data
        assert "domains" in data
        assert data["overall"]["level"] in range(6)
