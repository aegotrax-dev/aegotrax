"""Offline tests for security hardening (no engine required).

Run:
    python examples/security_hardening_test.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentguard.security_utils import (
    email_domain_allowed,
    hostname_allowed,
    intent_is_restrictive,
    is_url_blocked,
    normalize_arg_text,
    redact_arguments,
    tool_has_side_effects,
)


def test_url_ssrf_guard() -> None:
    cases = [
        ("http://169.254.169.254/latest/meta-data/", True),
        ("http://127.0.0.1:8080/admin", True),
        ("http://localhost/x", True),
        ("http://10.0.0.5/internal", True),
        ("http://192.168.1.1/", True),
        ("http://172.16.0.1/", True),
        ("https://evil.com", False),
        ("https://api.internal-analytics.com/log", False),
        ("file:///etc/passwd", True),
        ("", True),
    ]
    for url, expect_blocked in cases:
        blocked, reason = is_url_blocked(url)
        assert blocked is expect_blocked, f"{url}: blocked={blocked} reason={reason}"
    print("✅ SSRF / IMDS guard")


def test_hostname_allowlist_no_substring() -> None:
    allowed = ["api.internal-analytics.com"]
    assert hostname_allowed("https://api.internal-analytics.com/log", allowed)
    assert hostname_allowed("https://eu.api.internal-analytics.com/x", allowed)
    # classic substring bypasses — must FAIL
    assert not hostname_allowed(
        "https://evil.com/?x=https://api.internal-analytics.com/log", allowed
    )
    assert not hostname_allowed(
        "https://api.internal-analytics.com.evil.com/log", allowed
    )
    assert not hostname_allowed("https://evil.com", allowed)
    print("✅ Hostname allowlist (no substring bypass)")


def test_email_domain() -> None:
    trusted = ["@company.com", "company.com"]
    assert email_domain_allowed("alice@company.com", trusted)
    assert email_domain_allowed("bob@mail.company.com", trusted)
    assert not email_domain_allowed("alice@company.com.evil.com", trusted)
    assert not email_domain_allowed("alice@evil.com", trusted)
    assert not email_domain_allowed("not-an-email", trusted)
    print("✅ Email domain allowlist")


def test_intent_restrictive() -> None:
    assert intent_is_restrictive("Summarize the ticket only")
    assert intent_is_restrictive("Just summarize the document")
    assert intent_is_restrictive("Read only — do not send email")
    assert intent_is_restrictive("nothing else, just list users")
    assert not intent_is_restrictive("Help the customer with billing and email them the invoice")
    assert tool_has_side_effects("http_post")
    assert tool_has_side_effects("send_email")
    assert not tool_has_side_effects("read_document")  # tracked as sensitive, but pattern list
    print("✅ Intent constraint patterns")


def test_base64_normalization() -> None:
    import base64

    secret = "customer_db_record confidential"
    encoded = base64.b64encode(secret.encode()).decode()
    text = normalize_arg_text({"data": encoded})
    assert "customer" in text
    assert "confidential" in text
    print("✅ Base64 argument normalization")


def test_redaction() -> None:
    args = {
        "to": "a@b.com",
        "api_key": "sk-live-secret",
        "password": "hunter2",
        "body": "hello",
        "long": "x" * 500,
    }
    red = redact_arguments(args)
    assert red["api_key"] == "***REDACTED***"
    assert red["password"] == "***REDACTED***"
    assert red["to"] == "a@b.com"
    assert red["body"] == "hello"
    assert red["long"].endswith("…[truncated]")
    print("✅ Audit argument redaction")


def main() -> None:
    test_url_ssrf_guard()
    test_hostname_allowlist_no_substring()
    test_email_domain()
    test_intent_restrictive()
    test_base64_normalization()
    test_redaction()
    print("\nAll security hardening unit checks passed.")


if __name__ == "__main__":
    main()
