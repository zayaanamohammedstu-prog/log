"""
log_parser.py
-------------
Parses raw Apache Common Log Format (CLF) entries into a structured
pandas DataFrame suitable for feature engineering and anomaly detection.

Apache CLF example line:
  127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
"""

import re
import pandas as pd
from datetime import datetime

# Regex pattern for Apache Common Log Format
_CLF_PATTERN = re.compile(
    r'(?P<ip>\S+)'           # IP address
    r'\s+\S+'                # ident (usually -)
    r'\s+\S+'                # userid (usually -)
    r'\s+\[(?P<time>[^\]]+)\]'  # timestamp [dd/Mon/YYYY:HH:MM:SS ±HHMM]
    r'\s+"(?P<request>[^"]*)"'  # request line "METHOD /path HTTP/x.x"
    r'\s+(?P<status>\d{3})'  # HTTP status code
    r'\s+(?P<bytes>\S+)'     # bytes sent (may be -)
    r'(?:\s+"(?P<referer>[^"]*)")?'   # optional referer
    r'(?:\s+"(?P<user_agent>[^"]*)")?'  # optional user-agent
)

_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_time(raw: str) -> datetime | None:
    """Convert CLF timestamp string to a timezone-aware datetime."""
    try:
        return datetime.strptime(raw, _TIME_FORMAT)
    except ValueError:
        return None


def _split_request(request: str) -> tuple[str, str, str]:
    """Split 'METHOD /path HTTP/1.x' into its three components."""
    parts = request.split()
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return "", request, ""


def parse_log_file(path: str) -> pd.DataFrame:
    """
    Parse an Apache CLF log file and return a structured DataFrame.

    Parameters
    ----------
    path : str
        Path to the log file.

    Returns
    -------
    pd.DataFrame
        Columns: ip_address, timestamp, method, endpoint, protocol,
                 status_code, bytes_sent, referer, user_agent.
    """
    records = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            m = _CLF_PATTERN.match(line)
            if not m:
                continue
            g = m.groupdict()
            method, endpoint, protocol = _split_request(g["request"])
            records.append(
                {
                    "ip_address": g["ip"],
                    "timestamp": _parse_time(g["time"]),
                    "method": method.upper() if method else "",
                    "endpoint": endpoint,
                    "protocol": protocol,
                    "status_code": int(g["status"]),
                    "bytes_sent": (
                        int(g["bytes"]) if g["bytes"] not in ("-", None) else 0
                    ),
                    "referer": g.get("referer") or "",
                    "user_agent": g.get("user_agent") or "",
                }
            )

    df = pd.DataFrame(records)
    if df.empty:
        return df

    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


def parse_log_lines(lines: list[str]) -> pd.DataFrame:
    """
    Parse an iterable of raw CLF log strings.  Useful for testing and
    in-memory processing.

    Parameters
    ----------
    lines : list[str]
        Raw log lines.

    Returns
    -------
    pd.DataFrame
        Same schema as :func:`parse_log_file`.
    """
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write("\n".join(lines))
        tmp_path = tmp.name

    try:
        return parse_log_file(tmp_path)
    finally:
        os.unlink(tmp_path)
