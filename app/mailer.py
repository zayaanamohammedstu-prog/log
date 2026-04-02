"""
app/mailer.py
-------------
Send a report PDF via SMTP email.

Required environment variables
-------------------------------
LOGGUARD_SMTP_HOST     SMTP server hostname (e.g. smtp.gmail.com)
LOGGUARD_SMTP_PORT     SMTP port (default 587)
LOGGUARD_SMTP_USER     SMTP login username / sender address
LOGGUARD_SMTP_PASSWORD SMTP login password (or app-password)
LOGGUARD_SMTP_FROM     Optional override for the From address
                       (defaults to LOGGUARD_SMTP_USER)
"""

from __future__ import annotations

import os
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class MailerError(Exception):
    """Raised when email sending fails due to a configuration or network problem."""


def send_report_email(
    to_address: str,
    run_id: int,
    pdf_bytes: bytes,
    *,
    subject: str | None = None,
    body: str | None = None,
) -> None:
    """Send *pdf_bytes* as an email attachment to *to_address*.

    Parameters
    ----------
    to_address:
        Recipient email address.
    run_id:
        Numeric run identifier (used in default subject / filename).
    pdf_bytes:
        Raw PDF content to attach.
    subject:
        Optional email subject override.
    body:
        Optional plain-text body override.

    Raises
    ------
    MailerError
        When SMTP credentials are missing or the send operation fails.
    """
    smtp_host = os.environ.get("LOGGUARD_SMTP_HOST", "").strip()
    smtp_port = int(os.environ.get("LOGGUARD_SMTP_PORT", "587"))
    smtp_user = os.environ.get("LOGGUARD_SMTP_USER", "").strip()
    smtp_password = os.environ.get("LOGGUARD_SMTP_PASSWORD", "").strip()
    from_addr = os.environ.get("LOGGUARD_SMTP_FROM", smtp_user).strip()

    if not smtp_host or not smtp_user or not smtp_password:
        raise MailerError(
            "Email is not configured. Set LOGGUARD_SMTP_HOST, "
            "LOGGUARD_SMTP_USER, and LOGGUARD_SMTP_PASSWORD environment variables."
        )

    subject = subject or f"LogGuard Anomaly Detection Report — Run #{run_id}"
    body = body or (
        f"Please find attached the LogGuard anomaly detection report for Run #{run_id}.\n\n"
        "This report was generated automatically by LogGuard.\n"
    )

    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = to_address
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    attachment = MIMEBase("application", "octet-stream")
    attachment.set_payload(pdf_bytes)
    encoders.encode_base64(attachment)
    attachment.add_header(
        "Content-Disposition",
        "attachment",
        filename=f"logguard_report_run_{run_id}.pdf",
    )
    msg.attach(attachment)

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(from_addr, [to_address], msg.as_string())
    except smtplib.SMTPAuthenticationError:
        raise MailerError("SMTP authentication failed. Check your credentials.") from None
    except smtplib.SMTPConnectError:
        raise MailerError("Could not connect to the SMTP server. Check LOGGUARD_SMTP_HOST and LOGGUARD_SMTP_PORT.") from None
    except smtplib.SMTPException:
        raise MailerError("Failed to send email via SMTP. Check your SMTP configuration.") from None
    except OSError:
        raise MailerError("SMTP connection error. The server may be unreachable.") from None
