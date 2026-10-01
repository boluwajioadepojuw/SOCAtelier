"""Phishing analyzer tests: deterministic verdicts on crafted emails."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lynx"))

from phishing_analyzer import analyze_email  # noqa: E402

MALICIOUS = """From: "Microsoft Security" <security@ms-support-verify.tk>
Reply-To: attacker@example-evil.xyz
Return-Path: <bounce@spam-runner.ml>
Subject: Urgent: verify your password immediately
Content-Type: text/plain

Your account has been locked. Verify your password now:
http://185.12.44.9/login and also https://xn--mcrsoft-9ya.com/verify

Open the attached invoice to confirm payment.
"""

BENIGN = """From: Alice <alice@company.example>
Subject: Lunch tomorrow?
Content-Type: text/plain

Hey, are we still on for lunch tomorrow? Let me know.
"""


def test_malicious_email_scores_high():
    verdict = analyze_email(MALICIOUS)
    assert verdict["ok"] is True
    assert verdict["score"] >= 50
    assert verdict["risk"] in ("HIGH", "CRITICAL")


def test_malicious_email_flags_brand_impersonation():
    verdict = analyze_email(MALICIOUS)
    titles = [f["title"] for f in verdict["findings"]]
    assert "Brand impersonation" in titles
    assert "IP-literal URL" in titles
    assert "Punycode domain" in titles
    assert "Reply-To mismatch" in titles
    assert "Bait language" in titles


def test_malicious_email_maps_mitre_phishing_link():
    verdict = analyze_email(MALICIOUS)
    techs = [m["technique"] for m in verdict["mitre"]]
    assert "T1566.002" in techs
    assert "T1204.001" in techs


def test_benign_email_scores_low():
    verdict = analyze_email(BENIGN)
    assert verdict["score"] < 20
    assert verdict["risk"] == "LOW"


def test_attachment_maps_to_attachment_technique():
    raw = (
        "From: billing@corp.example\n"
        "Subject: Invoice\n"
        "Content-Disposition: attachment; filename=invoice.exe\n"
        "\n"
        "Please open the attached invoice.\n"
    )
    verdict = analyze_email(raw)
    assert "invoice.exe" in verdict["indicators"]["unsafe_attachments"]
    techs = [m["technique"] for m in verdict["mitre"]]
    assert "T1566.001" in techs
    assert "T1204.002" in techs


def test_authentication_results_parsed():
    raw = (
        "From: x@y.example\n"
        "Authentication-Results: mx.example; spf=fail smtp.mailfrom=y.example;\n"
        "\n"
        "body\n"
    )
    verdict = analyze_email(raw)
    assert verdict["authentication"]["spf_fail"] is True


def test_no_auth_headers_flagged():
    verdict = analyze_email(BENIGN)
    assert verdict["authentication"]["has_auth_headers"] is False
    titles = [f["title"] for f in verdict["findings"]]
    assert "No authentication headers" in titles
