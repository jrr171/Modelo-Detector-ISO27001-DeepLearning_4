"""
Log Parser — supports multiple log formats:
  - Apache / Nginx Combined / Common
  - Linux syslog / auth.log
  - Windows Event Log (CSV export from Event Viewer)
  - Generic / custom single-line logs
"""

import re
import os
import csv
import gzip
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Iterator

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """Normalised log entry regardless of source format."""
    timestamp: Optional[datetime]
    source_ip: Optional[str]
    user: Optional[str]
    level: str          # DEBUG / INFO / WARNING / ERROR / CRITICAL
    message: str
    raw: str
    log_file: str
    line_number: int


# ─────────────────────────────────────────────
# Format-specific regexes
# ─────────────────────────────────────────────

# Apache / Nginx Combined Log Format
APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# Linux syslog (rsyslog default)
SYSLOG_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.+)'
)

# ISO 8601 syslog (common in newer distros)
ISO_SYSLOG_PATTERN = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?)\s+'
    r'(?P<host>\S+)\s+(?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.+)'
)

# Windows Event Log CSV (from wevtutil / Event Viewer export)
WINDOWS_CSV_FIELDS = {
    "TimeCreated", "Id", "LevelDisplayName",
    "Message", "UserName", "Computer"
}

# Severity keywords → normalised level
SEVERITY_MAP = {
    "emerg":     "CRITICAL",
    "alert":     "CRITICAL",
    "crit":      "CRITICAL",
    "critical":  "CRITICAL",
    "err":       "ERROR",
    "error":     "ERROR",
    "warn":      "WARNING",
    "warning":   "WARNING",
    "notice":    "INFO",
    "info":      "INFO",
    "debug":     "DEBUG",
    "fatal":     "CRITICAL",
}


def _normalise_level(raw: str) -> str:
    return SEVERITY_MAP.get(raw.strip().lower(), "INFO")


def _http_status_to_level(status: int) -> str:
    if status >= 500:
        return "ERROR"
    if status >= 400:
        return "WARNING"
    return "INFO"


def _parse_apache_line(line: str, log_file: str, lineno: int) -> Optional[LogEntry]:
    m = APACHE_PATTERN.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        ts = None
    status = int(m.group("status"))
    msg = f'{m.group("request")} → {status}'
    return LogEntry(
        timestamp=ts,
        source_ip=m.group("ip"),
        user=m.group("user") if m.group("user") != "-" else None,
        level=_http_status_to_level(status),
        message=msg,
        raw=line,
        log_file=log_file,
        line_number=lineno,
    )


def _parse_syslog_line(line: str, log_file: str, lineno: int) -> Optional[LogEntry]:
    # Try ISO 8601 first
    m = ISO_SYSLOG_PATTERN.match(line)
    if m:
        try:
            ts = datetime.fromisoformat(m.group("time").replace("Z", "+00:00"))
        except ValueError:
            ts = None
        msg = m.group("message")
        level = _infer_level_from_message(msg)
        return LogEntry(
            timestamp=ts,
            source_ip=_extract_ip(msg),
            user=_extract_user(msg),
            level=level,
            message=msg,
            raw=line,
            log_file=log_file,
            line_number=lineno,
        )
    # Try traditional syslog
    m = SYSLOG_PATTERN.match(line)
    if m:
        current_year = datetime.now().year
        try:
            ts = datetime.strptime(
                f"{current_year} {m.group('month')} {m.group('day')} {m.group('time')}",
                "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            ts = None
        msg = m.group("message")
        level = _infer_level_from_message(msg)
        return LogEntry(
            timestamp=ts,
            source_ip=_extract_ip(msg),
            user=_extract_user(msg),
            level=level,
            message=msg,
            raw=line,
            log_file=log_file,
            line_number=lineno,
        )
    return None


def _parse_windows_csv_row(row: dict, log_file: str, lineno: int) -> Optional[LogEntry]:
    try:
        ts_str = row.get("TimeCreated", "")
        try:
            ts = datetime.fromisoformat(ts_str)
        except ValueError:
            ts = None
        raw_level = row.get("LevelDisplayName", "Information")
        level = _normalise_level(raw_level.split()[0])
        msg = row.get("Message", "")
        return LogEntry(
            timestamp=ts,
            source_ip=_extract_ip(msg),
            user=row.get("UserName") or _extract_user(msg),
            level=level,
            message=msg[:500],
            raw=str(row),
            log_file=log_file,
            line_number=lineno,
        )
    except Exception:
        return None


_LEVEL_RE = re.compile(
    r'\b(emerg|alert|crit(?:ical)?|err(?:or)?|warn(?:ing)?|notice|info|debug|fatal)\b',
    re.IGNORECASE
)
_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_USER_RE = re.compile(
    r'(?:user|from|for)\s+(\S+)',
    re.IGNORECASE
)


def _infer_level_from_message(msg: str) -> str:
    m = _LEVEL_RE.search(msg)
    if m:
        return _normalise_level(m.group(1))
    msg_lower = msg.lower()
    if any(w in msg_lower for w in ("critical", "panic", "fatal", "emergency",
                                     "out of memory", "out.of.memory", "oom")):
        return "CRITICAL"
    if any(w in msg_lower for w in ("failed", "failure", "denied", "error",
                                     "invalid", "blocked", "expired")):
        return "WARNING"
    return "INFO"


def _extract_ip(text: str) -> Optional[str]:
    m = _IP_RE.search(text)
    return m.group(1) if m else None


def _extract_user(text: str) -> Optional[str]:
    m = _USER_RE.search(text)
    return m.group(1) if m else None


# ─────────────────────────────────────────────
# Unified log reader
# ─────────────────────────────────────────────

class LogParser:
    """
    Reads one or more log files and yields normalised LogEntry objects.
    Supports .log, .txt, .gz, and .csv (Windows Event export).
    """

    SUPPORTED_EXTENSIONS = {".log", ".txt", ".gz", ".csv", ".json"}

    def __init__(self, max_lines: int = 500_000):
        self.max_lines = max_lines
        self.stats: dict = {
            "total_lines": 0,
            "parsed_ok": 0,
            "parse_errors": 0,
            "files_processed": 0,
        }

    # ── public API ──────────────────────────────

    def parse_path(self, path: str) -> List[LogEntry]:
        """Parse a file or directory; return all LogEntry objects."""
        entries: List[LogEntry] = []
        p = Path(path)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.suffix.lower() in self.SUPPORTED_EXTENSIONS and f.is_file():
                    entries.extend(self._parse_file(str(f)))
        elif p.is_file():
            entries.extend(self._parse_file(str(p)))
        else:
            raise FileNotFoundError(f"Path not found: {path}")
        return entries

    # ── internal ────────────────────────────────

    def _open_file(self, path: str):
        if path.endswith(".gz"):
            return gzip.open(path, "rt", errors="replace")
        return open(path, "r", errors="replace")

    def _parse_file(self, path: str) -> List[LogEntry]:
        ext = Path(path).suffix.lower()
        self.stats["files_processed"] += 1

        if ext == ".csv":
            return list(self._parse_csv(path))
        if ext == ".json":
            return list(self._parse_json(path))
        return list(self._parse_text(path))

    def _parse_text(self, path: str) -> Iterator[LogEntry]:
        """Attempt Apache, then syslog, then generic parse for each line."""
        format_hint = self._detect_format(path)
        with self._open_file(path) as fh:
            for lineno, line in enumerate(fh, 1):
                if lineno > self.max_lines:
                    logger.warning("Max lines reached for %s", path)
                    break
                self.stats["total_lines"] += 1
                line = line.rstrip("\n")
                if not line.strip():
                    continue

                entry = None
                if format_hint == "apache":
                    entry = _parse_apache_line(line, path, lineno)
                elif format_hint == "syslog":
                    entry = _parse_syslog_line(line, path, lineno)

                if entry is None:
                    # Try both
                    entry = _parse_apache_line(line, path, lineno) or \
                            _parse_syslog_line(line, path, lineno) or \
                            self._parse_generic(line, path, lineno)

                if entry:
                    self.stats["parsed_ok"] += 1
                    yield entry
                else:
                    self.stats["parse_errors"] += 1

    def _parse_csv(self, path: str) -> Iterator[LogEntry]:
        with open(path, newline="", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for lineno, row in enumerate(reader, 2):
                self.stats["total_lines"] += 1
                entry = _parse_windows_csv_row(row, path, lineno)
                if entry:
                    self.stats["parsed_ok"] += 1
                    yield entry
                else:
                    self.stats["parse_errors"] += 1

    def _parse_json(self, path: str) -> Iterator[LogEntry]:
        with open(path, errors="replace") as fh:
            try:
                data = json.load(fh)
                if isinstance(data, list):
                    records = data
                else:
                    records = [data]
            except json.JSONDecodeError:
                fh.seek(0)
                records = []
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

        for lineno, record in enumerate(records, 1):
            self.stats["total_lines"] += 1
            msg = (
                record.get("message") or
                record.get("msg") or
                record.get("log") or
                str(record)
            )
            raw_level = (
                record.get("level") or
                record.get("severity") or
                record.get("levelname") or
                "INFO"
            )
            ts_str = record.get("timestamp") or record.get("time") or record.get("@timestamp")
            try:
                ts = datetime.fromisoformat(str(ts_str)) if ts_str else None
            except ValueError:
                ts = None
            entry = LogEntry(
                timestamp=ts,
                source_ip=record.get("src_ip") or _extract_ip(msg),
                user=record.get("user") or _extract_user(msg),
                level=_normalise_level(str(raw_level)),
                message=str(msg)[:500],
                raw=str(record),
                log_file=path,
                line_number=lineno,
            )
            self.stats["parsed_ok"] += 1
            yield entry

    def _parse_generic(self, line: str, path: str, lineno: int) -> Optional[LogEntry]:
        """Fallback: extract whatever we can from an arbitrary log line."""
        if len(line) < 5:
            return None
        return LogEntry(
            timestamp=None,
            source_ip=_extract_ip(line),
            user=_extract_user(line),
            level=_infer_level_from_message(line),
            message=line[:500],
            raw=line,
            log_file=path,
            line_number=lineno,
        )

    def _detect_format(self, path: str) -> Optional[str]:
        """Read first non-empty line to guess format."""
        try:
            with self._open_file(path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    if APACHE_PATTERN.match(line):
                        return "apache"
                    if ISO_SYSLOG_PATTERN.match(line) or SYSLOG_PATTERN.match(line):
                        return "syslog"
                    return None
        except Exception:
            return None
