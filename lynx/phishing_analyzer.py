"""Phishing triage for the Lynx console.

Deterministic, offline analysis of a raw email (headers + body): extracts
indicators, checks the classic L1 phishing signals, scores the message and
maps findings onto MITRE ATT&CK. No AI service involved - the same offline
guarantee as the rest of the console.
"""

import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}", re.IGNORECASE)
PUNYCODE_RE = re.compile(r"\bxn--[a-z0-9-]+", re.IGNORECASE)
HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$")

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".icu",
    ".cyou", ".rest", ".buzz", ".click", ".link", ".zip", ".mov", ".country",
}
BAIT_WORDS = [
    "verify", "confirm", "password", "invoice", "payment", "suspended",
    "urgent", "expire", "expires", "billing", "support", "login", "unusual",
    "locked", "security", "account", "update", "click here", "immediately",
    "limited time", "final notice", "unusual activity",
]
SPOOF_BRANDS = [
    "microsoft", "paypal", "amazon", "apple", "google", "netflix",
    "facebook", "instagram", "linkedin", "dhl", "fedex", "ups",
    "coinbase", "binance", "dropbox", "adobe", "docusign",
]
FREE_MAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "protonmail.com", "icloud.com", "mail.com", "gmx.com", "live.com",
}
UNSAFE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jar", ".iso", ".img",
    ".lnk", ".hta", ".ps1", ".docm", ".xlsm", ".pptm", ".7z", ".rar", ".zip",
}
AUTH_HEADERS = {"spf": "authentication-results", "dkim": "authentication-results",
               "dmarc": "authentication-results"}


def _domain_of(address: str) -> str:
    """Lowercase domain part of an email address, or the address itself."""
    address = (address or "").strip().strip("<>")
    if "@" in address:
        return address.rsplit("@", 1)[1].lower()
    return address.lower()


def _split_raw(raw: str) -> tuple[dict, str]:
    """Split a raw message into header dict and body text."""
    headers: dict = {}
    body_lines: list = []
    in_body = False
    last_key: str | None = None
    for line in raw.splitlines():
        if not in_body and line == "":
            in_body = True
            continue
        if not in_body:
            m = HEADER_RE.match(line)
            if m:
                last_key = m.group(1).lower()
                headers.setdefault(last_key, []).append(m.group(2).strip())
            elif last_key and line.startswith((" ", "\t")):
                headers[last_key][-1] += " " + line.strip()
        else:
            body_lines.append(line)
    return headers, "\n".join(body_lines)


def _url_domains(urls: list) -> list:
    """Hostnames from a list of URLs, without ports."""
    out = []
    for u in urls:
        try:
            host = urlparse(u).hostname
        except ValueError:
            host = None
        if host:
            out.append(host.lower())
    return out


def analyze_email(raw: str) -> dict:
    """Analyze a raw email and return the triage verdict."""
    if not isinstance(raw, str):
        raw = ""
    headers, body = _split_raw(raw)

    from_hdr = (headers.get("from") or [""])[0]
    reply_to = (headers.get("reply-to") or [""])[0]
    return_path = (headers.get("return-path") or [""])[0]
    subject = (headers.get("subject") or [""])[0]

    from_match = EMAIL_RE.search(from_hdr)
    from_addr = from_match.group(0) if from_match else from_hdr
    display_name = from_hdr.split("<")[0].strip().strip('"') if "<" in from_hdr else ""
    from_domain = _domain_of(from_addr)

    urls = URL_RE.findall(body)
    url_domains = _url_domains(urls)
    ip_literal_urls = [u for u in urls if IP_URL_RE.match(u)]
    punycode_domains = sorted({d for d in url_domains if PUNYCODE_RE.search(d)})
    ips = sorted(set(IP_RE.findall(body)))
    attachments = []
    for name, values in headers.items():
        if name == "content-disposition":
            for v in values:
                fm = re.search(r'filename="?([^";]+)"?', v, re.IGNORECASE)
                if fm:
                    attachments.append(fm.group(1).strip())

    # Authentication headers
    auth_text = " ".join(headers.get("authentication-results", [])).lower()
    spf_fail = "spf=fail" in auth_text or "spf=softfail" in auth_text
    dkim_fail = "dkim=fail" in auth_text
    dmarc_fail = "dmarc=fail" in auth_text
    has_auth = bool(headers.get("authentication-results"))

    findings = []
    lower_body = (body or "").lower()
    lower_subject = (subject or "").lower()
    lower_display = (display_name or "").lower()

    # Brand impersonation: display name claims a brand but sender domain
    # is unrelated (usually a free mailbox).
    claimed_brands = [b for b in SPOOF_BRANDS if b in lower_display or b in lower_subject]
    brand_domain_ok = any(b in from_domain for b in claimed_brands)
    if claimed_brands and not brand_domain_ok:
        findings.append({
            "title": "Brand impersonation",
            "detail": f"claims {', '.join(claimed_brands)} but sends from {from_domain}",
            "weight": 35,
        })
    if claimed_brands and from_domain in FREE_MAIL:
        findings.append({
            "title": "Free-mail sender",
            "detail": f"brand context delivered from free mailbox {from_domain}",
            "weight": 15,
        })

    # Reply path divergence
    reply_domain = _domain_of(reply_to) if reply_to else ""
    if reply_domain and reply_domain != from_domain:
        findings.append({
            "title": "Reply-To mismatch",
            "detail": f"Reply-To ({reply_domain}) differs from From ({from_domain})",
            "weight": 30,
        })
    rp_domain = _domain_of(return_path) if return_path else ""
    if rp_domain and rp_domain != from_domain:
        findings.append({
            "title": "Return-Path mismatch",
            "detail": f"Return-Path ({rp_domain}) differs from From ({from_domain})",
            "weight": 20,
        })

    # Authentication
    if spf_fail:
        findings.append({"title": "SPF failed", "detail": "sender not authorized for the From domain", "weight": 20})
    if dkim_fail:
        findings.append({"title": "DKIM failed", "detail": "signature invalid or missing", "weight": 20})
    if dmarc_fail:
        findings.append({"title": "DMARC failed", "detail": "alignment failed for the From domain", "weight": 25})
    if not has_auth:
        findings.append({"title": "No authentication headers", "detail": "SPF/DKIM/DMARC results absent", "weight": 10})

    # Links
    if ip_literal_urls:
        findings.append({
            "title": "IP-literal URL",
            "detail": ", ".join(ip_literal_urls[:3]),
            "weight": 30,
        })
    if punycode_domains:
        findings.append({
            "title": "Punycode domain",
            "detail": ", ".join(punycode_domains[:3]),
            "weight": 25,
        })
    suspicious_tlds = sorted({d for d in url_domains if any(d.endswith(t) for t in SUSPICIOUS_TLDS)})
    if suspicious_tlds:
        findings.append({
            "title": "Suspicious TLD",
            "detail": ", ".join(suspicious_tlds[:3]),
            "weight": 15,
        })
    external_links = [d for d in url_domains if d != from_domain]
    if urls and external_links:
        findings.append({
            "title": "External links",
            "detail": f"{len(external_links)} link(s) point outside the sender domain",
            "weight": 15,
        })

    # Attachments
    unsafe_attachments = [a for a in attachments if any(a.lower().endswith(e) for e in UNSAFE_EXTENSIONS)]
    if unsafe_attachments:
        findings.append({
            "title": "Unsafe attachment type",
            "detail": ", ".join(unsafe_attachments[:3]),
            "weight": 30,
        })

    # Urgency / credential bait
    bait_hits = [w for w in BAIT_WORDS if w in lower_body or w in lower_subject]
    if bait_hits:
        findings.append({
            "title": "Bait language",
            "detail": ", ".join(sorted(set(bait_hits))[:6]),
            "weight": 10,
        })

    score = min(100, sum(f["weight"] for f in findings))
    risk = "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM" if score >= 20 else "LOW"

    # MITRE mapping
    mitre = []
    if unsafe_attachments:
        mitre.append({"technique": "T1566.001", "name": "Phishing: Spearphishing Attachment", "reason": "attachment with executable/scriptable extension"})
        mitre.append({"technique": "T1204.002", "name": "User Execution: Malicious File", "reason": "user must open the delivered file"})
    if urls:
        mitre.append({"technique": "T1566.002", "name": "Phishing: Spearphishing Link", "reason": "message carries clickable URLs"})
        mitre.append({"technique": "T1204.001", "name": "User Execution: Malicious Link", "reason": "user must click the delivered link"})
    if claimed_brands and not brand_domain_ok:
        mitre.append({"technique": "T1566", "name": "Phishing", "reason": "brand impersonation in sender display name"})
    if not mitre:
        mitre.append({"technique": "T1566", "name": "Phishing", "reason": "message triaged for phishing signals"})

    next_steps = []
    if score >= 50:
        next_steps.append("Block sender domain and reply-to domain at the gateway.")
        next_steps.append("Quarantine the message and any lookalike messages from the last 24h.")
    if unsafe_attachments:
        next_steps.append("Detonate the attachment in a sandbox; do not open it on a production host.")
    if urls:
        next_steps.append("Submit URLs to a URL scanner; check the destination registrant age.")
    if score < 50:
        next_steps.append("Low signal - file as false positive reference or keep for awareness training.")
    next_steps.append("Log the triage in the analyst action trail with the final verdict.")

    return {
        "ok": True,
        "score": score,
        "risk": risk,
        "sender": {
            "from": from_addr,
            "display_name": display_name,
            "reply_to": reply_to or None,
            "return_path": return_path or None,
            "from_domain": from_domain,
        },
        "subject": subject,
        "indicators": {
            "urls": urls,
            "url_domains": sorted(set(url_domains)),
            "ip_literal_urls": ip_literal_urls,
            "punycode_domains": punycode_domains,
            "suspicious_tld_domains": suspicious_tlds,
            "ips": ips,
            "attachments": attachments,
            "unsafe_attachments": unsafe_attachments,
        },
        "authentication": {
            "has_auth_headers": has_auth,
            "spf_fail": spf_fail,
            "dkim_fail": dkim_fail,
            "dmarc_fail": dmarc_fail,
        },
        "findings": findings,
        "mitre": mitre,
        "next_steps": next_steps,
    }
