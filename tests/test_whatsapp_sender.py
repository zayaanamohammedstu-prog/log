"""
tests/test_whatsapp_sender.py
-----------------------------
Unit tests for the Meta WhatsApp Business Cloud API sender.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest
import requests as req

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from whatsapp_sender import WhatsAppSenderError, send_report_whatsapp  # noqa: E402


class TestSendReportWhatsapp:
    """Tests for send_report_whatsapp()."""

    _ENV = {
        "WHATSAPP_PHONE_NUMBER_ID": "123456789",
        "WHATSAPP_ACCESS_TOKEN": "test_access_token",
    }

    def _mock_ok_response(self):
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        return resp

    def _mock_error_response(self, status_code: int, message: str):
        resp = MagicMock()
        resp.ok = False
        resp.status_code = status_code
        resp.json.return_value = {"error": {"message": message}}
        return resp

    def test_raises_when_credentials_missing(self):
        """Should raise WhatsAppSenderError when env vars are not set."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(WhatsAppSenderError, match="WHATSAPP_PHONE_NUMBER_ID"):
                send_report_whatsapp("+447911123456", 1, "https://example.com/report.pdf")

    def test_raises_when_only_phone_number_id_set(self):
        env = {"WHATSAPP_PHONE_NUMBER_ID": "123"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(WhatsAppSenderError, match="WHATSAPP_ACCESS_TOKEN"):
                send_report_whatsapp("+447911123456", 1, "https://example.com/report.pdf")

    def test_raises_for_invalid_phone_number(self):
        with patch.dict(os.environ, self._ENV, clear=True):
            with pytest.raises(WhatsAppSenderError, match="Invalid recipient phone number"):
                send_report_whatsapp("not-a-number", 1, "https://example.com/report.pdf")

    def test_successful_send(self):
        """A well-formed call with valid config should POST to the Graph API."""
        with patch.dict(os.environ, self._ENV, clear=True):
            with patch("whatsapp_sender.requests.post") as mock_post:
                mock_post.return_value = self._mock_ok_response()
                # Should not raise
                send_report_whatsapp("+447911123456", 42, "https://example.com/report.pdf")

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        url = call_kwargs[0][0]
        assert "123456789" in url
        assert "messages" in url
        payload = call_kwargs[1]["json"]
        assert payload["messaging_product"] == "whatsapp"
        assert payload["to"] == "447911123456"  # leading + stripped
        assert payload["type"] == "document"
        assert "link" in payload["document"]
        assert payload["document"]["link"] == "https://example.com/report.pdf"

    def test_strips_leading_plus_from_number(self):
        """Phone numbers with leading + should be normalised for the API."""
        with patch.dict(os.environ, self._ENV, clear=True):
            with patch("whatsapp_sender.requests.post") as mock_post:
                mock_post.return_value = self._mock_ok_response()
                send_report_whatsapp("+447911123456", 1, "https://example.com/r.pdf")

        payload = mock_post.call_args[1]["json"]
        assert payload["to"] == "447911123456"

    def test_number_without_plus_also_works(self):
        with patch.dict(os.environ, self._ENV, clear=True):
            with patch("whatsapp_sender.requests.post") as mock_post:
                mock_post.return_value = self._mock_ok_response()
                send_report_whatsapp("447911123456", 1, "https://example.com/r.pdf")

        payload = mock_post.call_args[1]["json"]
        assert payload["to"] == "447911123456"

    def test_custom_body_used_as_caption(self):
        with patch.dict(os.environ, self._ENV, clear=True):
            with patch("whatsapp_sender.requests.post") as mock_post:
                mock_post.return_value = self._mock_ok_response()
                send_report_whatsapp(
                    "+447911123456",
                    5,
                    "https://example.com/r.pdf",
                    body="Custom caption",
                )

        payload = mock_post.call_args[1]["json"]
        assert payload["document"]["caption"] == "Custom caption"

    def test_default_caption_contains_run_id(self):
        with patch.dict(os.environ, self._ENV, clear=True):
            with patch("whatsapp_sender.requests.post") as mock_post:
                mock_post.return_value = self._mock_ok_response()
                send_report_whatsapp("+447911123456", 99, "https://example.com/r.pdf")

        payload = mock_post.call_args[1]["json"]
        assert "99" in payload["document"]["caption"]

    def test_raises_on_api_error_response(self):
        with patch.dict(os.environ, self._ENV, clear=True):
            with patch("whatsapp_sender.requests.post") as mock_post:
                mock_post.return_value = self._mock_error_response(
                    400, "Invalid phone number"
                )
                with pytest.raises(WhatsAppSenderError, match="400"):
                    send_report_whatsapp(
                        "+447911123456", 1, "https://example.com/r.pdf"
                    )

    def test_raises_on_network_error(self):
        with patch.dict(os.environ, self._ENV, clear=True):
            with patch("whatsapp_sender.requests.post") as mock_post:
                mock_post.side_effect = req.RequestException("Connection refused")
                with pytest.raises(WhatsAppSenderError, match="Network error"):
                    send_report_whatsapp(
                        "+447911123456", 1, "https://example.com/r.pdf"
                    )

    def test_authorization_header_set(self):
        with patch.dict(os.environ, self._ENV, clear=True):
            with patch("whatsapp_sender.requests.post") as mock_post:
                mock_post.return_value = self._mock_ok_response()
                send_report_whatsapp("+447911123456", 1, "https://example.com/r.pdf")

        headers = mock_post.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer test_access_token"

    def test_custom_api_version(self):
        env = {**self._ENV, "WHATSAPP_API_VERSION": "v20.0"}
        with patch.dict(os.environ, env, clear=True):
            with patch("whatsapp_sender.requests.post") as mock_post:
                mock_post.return_value = self._mock_ok_response()
                send_report_whatsapp("+447911123456", 1, "https://example.com/r.pdf")

        url = mock_post.call_args[0][0]
        assert "v20.0" in url
