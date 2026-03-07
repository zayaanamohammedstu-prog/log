"""
tests/test_parser.py
--------------------
Unit tests for pipeline.log_parser.
"""

import pytest
import pandas as pd
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.log_parser import parse_log_lines, parse_log_file


# ── Fixtures ─────────────────────────────────────────────────────────────────

VALID_COMBINED = (
    '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] '
    '"GET /apache_pb.gif HTTP/1.0" 200 2326 '
    '"http://www.example.com/start.html" "Mozilla/4.08"'
)

VALID_CLF = (
    '10.0.0.1 - - [15/Jan/2024:08:00:00 +0000] '
    '"POST /login HTTP/1.1" 401 128'
)

MALFORMED = "This is not a log line at all."


# ── Tests ────────────────────────────────────────────────────────────────────

class TestParseLogLines:
    def test_combined_log_format(self):
        df = parse_log_lines([VALID_COMBINED])
        assert len(df) == 1
        row = df.iloc[0]
        assert row["ip_address"] == "127.0.0.1"
        assert row["method"] == "GET"
        assert row["endpoint"] == "/apache_pb.gif"
        assert row["status_code"] == 200
        assert row["bytes_sent"] == 2326

    def test_clf_without_referer_ua(self):
        df = parse_log_lines([VALID_CLF])
        assert len(df) == 1
        row = df.iloc[0]
        assert row["ip_address"] == "10.0.0.1"
        assert row["method"] == "POST"
        assert row["status_code"] == 401
        assert row["bytes_sent"] == 128

    def test_malformed_lines_skipped(self):
        df = parse_log_lines([MALFORMED])
        assert df.empty

    def test_mixed_valid_invalid(self):
        df = parse_log_lines([VALID_COMBINED, MALFORMED, VALID_CLF])
        assert len(df) == 2

    def test_timestamp_parsed(self):
        df = parse_log_lines([VALID_COMBINED])
        assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])
        assert df["timestamp"].iloc[0].year == 2000

    def test_bytes_dash_becomes_zero(self):
        line = (
            '192.168.1.1 - - [15/Jan/2024:09:00:00 +0000] '
            '"GET / HTTP/1.1" 304 -'
        )
        df = parse_log_lines([line])
        assert df.iloc[0]["bytes_sent"] == 0

    def test_empty_input(self):
        df = parse_log_lines([])
        assert df.empty

    def test_columns_present(self):
        df = parse_log_lines([VALID_COMBINED])
        expected = {
            "ip_address", "timestamp", "method", "endpoint",
            "protocol", "status_code", "bytes_sent", "referer", "user_agent",
        }
        assert expected.issubset(set(df.columns))

    def test_sorted_by_timestamp(self):
        lines = [
            '10.0.0.2 - - [15/Jan/2024:10:00:00 +0000] "GET /b HTTP/1.1" 200 100',
            '10.0.0.1 - - [15/Jan/2024:08:00:00 +0000] "GET /a HTTP/1.1" 200 100',
        ]
        df = parse_log_lines(lines)
        assert df.iloc[0]["ip_address"] == "10.0.0.1"


class TestParseLogFile:
    def test_sample_log_file(self):
        path = os.path.join(os.path.dirname(__file__), "..", "data", "sample_logs.txt")
        if not os.path.exists(path):
            pytest.skip("sample_logs.txt not present")
        df = parse_log_file(path)
        assert len(df) > 0
        assert "ip_address" in df.columns
        assert "status_code" in df.columns

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_log_file("/nonexistent/path/to.log")
