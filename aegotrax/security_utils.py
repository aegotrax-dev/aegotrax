"""Security helpers: URL parsing, allowlists, redaction, obfuscation checks.

Used by the risk engine and MCP gateway to close common bypasses.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Private / dangerous network ranges (SSRF / IMDS)
# ---------------------------------------------------------------------------

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # link-local + AWS/GCP IMDS
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata",
    "metadata.google.internal",
    "metadata.google",
}


def _host_is_private_or_blocked(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return True
    if h in _BLOCKED_HOSTNAMES:
        return True
    # bare IP?
    try:
        ip = ipaddress.ip_address(h)
        return any(ip in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        pass
    # hostname ending with blocked labels
    if h.endswith(".localhost") or h.endswith(".local") or h.endswith(".internal"):
        return True
    return False


def parse_url_safe(url: str) -> Optional[Tuple[str, str, str]]:
    """
    Parse URL → (scheme, hostname, normalized).
    Returns None if unparseable or missing host.
    """
    raw = (url or "").strip()
    if not raw:
        return None
    # Add scheme if missing so urlparse works
    if "://" not in raw:
        raw = "https://" + raw
    try:
        p = urlparse(raw)
    except Exception:
        return None
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()
    if not host:
        return None
    return scheme, host, f"{scheme}://{host}"


def is_url_blocked(url: str) -> Tuple[bool, str]:
    """
    Return (blocked, reason). Blocks private/IMDS/link-local and non-http(s).
    """
    parsed = parse_url_safe(url)
    if parsed is None:
        return True, "unparseable or missing host"
    scheme, host, _ = parsed
    if scheme not in ("http", "https"):
        return True, f"scheme '{scheme}' not allowed"
    if _host_is_private_or_blocked(host):
        return True, f"host '{host}' is private/IMDS/link-local"
    return False, ""


def hostname_allowed(url_or_host: str, allowed_hosts: List[str]) -> bool:
    """
    Strict hostname allowlist (exact match or subdomain of an allowed suffix).
    Does NOT use naive substring 'in'.
    allowed_hosts entries may be full URLs or bare hostnames.
    """
    parsed = parse_url_safe(url_or_host)
    if parsed is None:
        # maybe bare hostname
        host = (url_or_host or "").strip().lower().split("/")[0].split(":")[0]
    else:
        host = parsed[1]

    if not host:
        return False

    for entry in allowed_hosts or []:
        entry = (entry or "").strip().lower()
        if not entry:
            continue
        # extract host from entry if it's a URL
        ep = parse_url_safe(entry)
        allowed_host = ep[1] if ep else entry.split("/")[0].split("@")[-1]
        if not allowed_host:
            continue
        if host == allowed_host or host.endswith("." + allowed_host):
            return True
    return False


def email_domain_allowed(address: str, trusted_domains: List[str]) -> bool:
    """
    Check email recipient against trusted domains.
    trusted_domains entries look like '@company.com' or 'company.com'.
    Rejects attacker@company.com.evil.com style tricks.
    """
    addr = (address or "").strip().lower()
    if "@" not in addr:
        return False
    # basic structural check
    local, _, domain = addr.rpartition("@")
    if not local or not domain or " " in addr:
        return False
    domain = domain.rstrip(".")

    for td in trusted_domains or []:
        td = (td or "").strip().lower()
        if td.startswith("@"):
            td = td[1:]
        if not td:
            continue
        if domain == td or domain.endswith("." + td):
            return True
    return False


# ---------------------------------------------------------------------------
# Argument normalization / light de-obfuscation
# ---------------------------------------------------------------------------

_B64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")


def _try_b64_decode(s: str) -> Optional[str]:
    if not _B64_RE.match(s.strip()):
        return None
    try:
        raw = base64.b64decode(s.strip(), validate=True)
        text = raw.decode("utf-8", errors="ignore")
        # only keep if it looks like printable text
        if text and sum(c.isprintable() or c.isspace() for c in text) / max(len(text), 1) > 0.8:
            return text
    except Exception:
        return None
    return None


def normalize_arg_text(value: Any, depth: int = 0) -> str:
    """
    Flatten arguments to a searchable lowercase string.
    Attempts one-level base64 decode on long tokens.
    """
    if depth > 4:
        return ""
    if value is None:
        return ""
    if isinstance(value, (int, float, bool)):
        return str(value).lower()
    if isinstance(value, str):
        parts = [value.lower()]
        decoded = _try_b64_decode(value)
        if decoded:
            parts.append(decoded.lower())
        return " ".join(parts)
    if isinstance(value, dict):
        return " ".join(normalize_arg_text(v, depth + 1) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(normalize_arg_text(v, depth + 1) for v in value)
    return str(value).lower()


# ---------------------------------------------------------------------------
# Intent constraint helpers
# ---------------------------------------------------------------------------

_RESTRICTIVE_PATTERNS = [
    re.compile(r"\bonly\b", re.I),
    re.compile(r"\bjust\b.*\b(summarize|read|list|show|display)\b", re.I),
    re.compile(r"\b(read|view|summarize)\s+only\b", re.I),
    re.compile(r"\bnothing\s+else\b", re.I),
    re.compile(r"\bdo\s+not\s+(send|post|email|execute|write|delete|export)\b", re.I),
    re.compile(r"\bdon't\s+(send|post|email|execute|write|delete|export)\b", re.I),
    re.compile(r"\bno\s+(outbound|external|email|posting|writes?)\b", re.I),
]

# Tools that change something or move data out. Plain reads (read_db, list_users,
# query_customers, read_document) are deliberately NOT here (0.2.8): a "read-only" or
# "list only" intent must not hard-block the very reads it permits. Reads are
# governed by session scope, read budgets and the sensitivity ceiling instead.
_SIDE_EFFECT_TOOLS = {
    "send_email",
    "email",
    "http_post",
    "http_request",
    "webhook",
    "execute_script",
    "run_code",
    "shell",
    "execute_code",
    "run_shell",
    "export_records",
    "get_ssn",
    "write_file",
    "delete_file",
    "delete_user",
}


def intent_is_restrictive(intent: str) -> bool:
    text = intent or ""
    return any(p.search(text) for p in _RESTRICTIVE_PATTERNS)


def tool_has_side_effects(tool: str, extra: Optional[Iterable[str]] = None) -> bool:
    """True if the tool changes state or sends data out.

    `extra` lets the caller add tool names from policy (e.g. code_execution_tools,
    side_effect_tools) so the heuristic follows the operator's own tool names.
    """
    name = (tool or "").lower()
    if name in _SIDE_EFFECT_TOOLS:
        return True
    return name in {str(t).lower() for t in (extra or [])}


# ---------------------------------------------------------------------------
# Keyword matching for script arguments
# ---------------------------------------------------------------------------

# Keywords this short ("rm", "dd") are matched as whole tokens: as bare substrings they
# hit ordinary words ("fo-rm-at", "a-dd-ress"). Longer keywords keep substring matching
# so "wipe" still matches "wipe_logs.sh" and "wipelogs".
_SHORT_KEYWORD_MAX_LEN = 3


def contains_keyword(text: str, keyword: str) -> bool:
    """Match a policy keyword against already-lowercased text."""
    kw = (keyword or "").strip().lower()
    if not kw:
        return False
    if len(kw) > _SHORT_KEYWORD_MAX_LEN:
        return kw in text
    return re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", text) is not None


# ---------------------------------------------------------------------------
# Audit redaction
# ---------------------------------------------------------------------------

_SENSITIVE_KEY_RE = re.compile(
    r"(password|secret|token|api[_-]?key|authorization|ssn|credit|_key$)",
    re.I,
)


def redact_arguments(arguments: Dict[str, Any], max_str_len: int = 200) -> Dict[str, Any]:
    """Return a copy of arguments safe for audit logs."""
    out: Dict[str, Any] = {}
    for k, v in (arguments or {}).items():
        key = str(k)
        if _SENSITIVE_KEY_RE.search(key):
            out[key] = "***REDACTED***"
            continue
        if isinstance(v, str):
            out[key] = v if len(v) <= max_str_len else v[:max_str_len] + "…[truncated]"
        elif isinstance(v, dict):
            out[key] = redact_arguments(v, max_str_len)
        elif isinstance(v, list) and len(v) > 20:
            out[key] = v[:20] + ["…[truncated]"]
        else:
            out[key] = v
    return out
