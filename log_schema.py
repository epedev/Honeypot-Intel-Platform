"""
Canonical schema for honeypot events.

Every bait route (admin login, .env, .git/config, IDOR API) almost certainly
logs a slightly different JSON shape. This module is the single place that
maps "whatever the Flask app wrote" into one consistent shape before
anything touches Postgres or Grafana.

IMPORTANT: I don't have a sample of your actual raw log lines, so the key
names below (timestamp/time/ts, source_ip/ip/remote_addr, etc.) are
defensive guesses covering common Flask logging patterns — not confirmed
to match your decoy app. Open normalize_event() and adjust the .get() keys
to match what your bait routes actually write before you trust this.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# --- route -> attack category mapping -------------------------------------
# Extend this as you add bait routes. Matches on substring of the path.
# ORDER MATTERS: categorize_route() returns on the FIRST substring match,
# in dict insertion order. More specific / higher-severity patterns must
# come before broad/generic ones, or a specific hit gets miscategorized
# by a generic prefix rule that happens to appear earlier.
ROUTE_CATEGORY_MAP = {

    # Named CVE probes (checked before generic file-disclosure patterns)
    "dana-na/auth": "known_cve_probe",           # Pulse Secure / Ivanti CVE-2019-11510
    "oauth1-credential/auth": "known_cve_probe", # Jenkins credential/auth-bypass probe

    # Information leakage: config & environment files
    "wp-config.php": "sensitive_file_disclosure",
    "database.sql": "sensitive_file_disclosure",
    "db.sql": "sensitive_file_disclosure",
    "database.yml": "sensitive_file_disclosure",
    "secrets.json": "sensitive_file_disclosure",
    "credentials.json": "sensitive_file_disclosure",
    "application.yml": "sensitive_file_disclosure",
    "application.properties": "sensitive_file_disclosure",
    "settings.json": "sensitive_file_disclosure",
    "config.json": "sensitive_file_disclosure",
    "config.js": "sensitive_file_disclosure",
    "config.yaml": "sensitive_file_disclosure",
    "config.php": "sensitive_file_disclosure",
    "live_env": "sensitive_file_disclosure",
    "phpinfo": "info_disclosure",
    "info.php": "info_disclosure",

    # Credential access
    "/admin": "credential_access",
    "/login": "credential_access",
    "+CSCOE+": "credential_access",          # Cisco ASA VPN
    "/remote/login": "credential_access",    # network appliance VPN portals

    # Sensitive file disclosure
    "/.env": "sensitive_file_disclosure",
    "/.git/": "sensitive_file_disclosure",   # covers .git/config AND .git/HEAD
    ".aws/credentials": "sensitive_file_disclosure",
    ".aws/config": "sensitive_file_disclosure",
    ".ssh/id_rsa": "sensitive_file_disclosure",
    ".ssh/authorized_keys": "sensitive_file_disclosure",
    ".npmrc": "sensitive_file_disclosure",
    ".netrc": "sensitive_file_disclosure",
    ".pgpass": "sensitive_file_disclosure",
    ".htpasswd": "sensitive_file_disclosure",
    ".docker/config.json": "sensitive_file_disclosure",
    ".kube/config": "sensitive_file_disclosure",
    "terraform.tfstate": "sensitive_file_disclosure",
    ".codex/auth.json": "sensitive_file_disclosure",  # AI CLI cred harvesting — call out by name in report writeups even though grouped here
    ".svn/": "sensitive_file_disclosure",
    ".DS_Store": "sensitive_file_disclosure",
    "docker-compose": "sensitive_file_disclosure",
    "appsettings": "sensitive_file_disclosure",
    "web.config": "sensitive_file_disclosure",
    "dump.sql": "sensitive_file_disclosure",
    "backup.sql": "sensitive_file_disclosure",

    # RCE attempts
    "phpunit": "rce_attempt",
    "eval-stdin": "rce_attempt",
    "think\\app": "rce_attempt",
    "invokefunction": "rce_attempt",
    "pearcmd": "rce_attempt",
    "cgi-bin": "rce_attempt",               # path traversal to /bin/sh

    # Known CVE probes
    "ReportServer": "known_cve_probe",       # SSRS
    "geoserver": "known_cve_probe",          # GeoServer RCE CVE-2024
    "metadatauploader": "known_cve_probe",   # DotNetNuke / SAP NetWeaver
    "SDK/webLanguage": "known_cve_probe",    # Hikvision CVE-2021-36260
    "doc/index.html": "known_cve_probe",
    "/actuator/": "known_cve_probe",         # Spring Boot Actuator, CVE-2022-22963/22965 chain
    "_profiler/open": "known_cve_probe",     # Symfony profiler LFI

    # Infrastructure recon
    "/containers/json": "infra_recon",
    "/mcp": "infra_recon",                   # AI/MCP server probe
    "/sse": "infra_recon",                   # Server-sent events probe
    "/v2/_catalog": "infra_recon",           # Docker registry API
    "/debug/vars": "infra_recon",            # Go expvar
    "/server-status": "infra_recon",         # Apache mod_status

    # Generic scanner fingerprinting
    "/api/": "idor_probe",
    "/favicon.ico": "scanner_fingerprint",
    "/robots.txt": "scanner_fingerprint",
    "/sitemap.xml": "scanner_fingerprint",
    "/index.php": "scanner_fingerprint",
    "/index.html": "scanner_fingerprint",
    "/hello.world": "scanner_fingerprint",
    "/.well-known/": "scanner_fingerprint",
    "web/": "scanner_fingerprint",
    "/ts2021": "scanner_fingerprint",
}

# Fallback heuristic: used only when no exact ROUTE_CATEGORY_MAP pattern
# matches. Broad keyword match on credential/secret-flavored paths that
# don't hit an exact filename entry (arbitrary naming variants scanners use).
CREDENTIAL_KEYWORDS = (
    "credential", "secret", "password", "auth", "token", "keyfile",
    "service-account", "adminsdk", "rsa", "tfvars", "tfstate", ".cnf",
)


def categorize_route(route: str, query: str = "") -> str:
    query_lower = (query or "").lower()
    if "allow_url_include" in query_lower and "auto_prepend_file" in query_lower:
        return "cve_2024_4577_rce"
    if route == "/":                      # exact match only — never substring-match root
        return "scanner_fingerprint"
    for pattern, category in ROUTE_CATEGORY_MAP.items():
        if pattern in route:
            return category
    route_lower = route.lower()
    if any(kw in route_lower for kw in CREDENTIAL_KEYWORDS):
        return "sensitive_file_disclosure"
    return "unknown"


@dataclass
class HoneypotEvent:
    event_timestamp: datetime
    source_ip: str
    route_hit: str
    http_method: str
    attack_category: str
    resp_status: int | None = None
    src_port: str | None = None
    query: str | None = None
    user_agent: str | None = None
    headers: dict[str, Any] = field(default_factory=dict)
    payload: Any = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def event_hash(self) -> str:
        """Stable id for dedup — same event ingested twice gets the same hash."""
        basis = (
            f"{self.event_timestamp.isoformat()}|{self.source_ip}|"
            f"{self.route_hit}|{json.dumps(self.payload, sort_keys=True)}"
        )
        return hashlib.sha256(basis.encode()).hexdigest()

    def to_db_row(self) -> dict[str, Any]:
        return {
            "event_hash": self.event_hash,
            "event_timestamp": self.event_timestamp,
            "source_ip": self.source_ip,
            "route_hit": self.route_hit,
            "attack_category": self.attack_category,
            "http_method": self.http_method,
            "resp_status": self.resp_status,
            "src_port": self.src_port,
            "query": self.query,
            "user_agent": self.user_agent,
            "headers": self.headers,
            "payload": self.payload,
            "raw": self.raw,
        }


class NormalizationError(ValueError):
    """Raised when a raw log line can't be mapped to HoneypotEvent."""


def normalize_event(raw: dict[str, Any]) -> HoneypotEvent:
    """
    Map one raw log dict (as written by the Flask honeypot) into a
    HoneypotEvent. Raises NormalizationError on anything that doesn't fit —
    callers should catch this and quarantine the line, not skip it silently.
    """
    try:
        ts_raw = raw.get("timestamp") or raw.get("time") or raw.get("ts")
        if ts_raw is None:
            raise NormalizationError("missing timestamp field")

        if isinstance(ts_raw, (int, float)):
            event_timestamp = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
        else:
            event_timestamp = datetime.fromisoformat(str(ts_raw))
            if event_timestamp.tzinfo is None:
                event_timestamp = event_timestamp.replace(tzinfo=timezone.utc)

        source_ip = raw.get("src_ip") or raw.get("source_ip") or raw.get("ip") or raw.get("remote_addr")
        route_hit = raw.get("path") or raw.get("route") or raw.get("endpoint")
        http_method = raw.get("method") or raw.get("http_method") or "UNKNOWN"

        if not source_ip or not route_hit:
            raise NormalizationError(f"missing source_ip or route_hit: {raw}")

        return HoneypotEvent(
            event_timestamp=event_timestamp,
            source_ip=str(source_ip),
            route_hit=str(route_hit),
            http_method=str(http_method).upper(),
            attack_category=categorize_route(str(route_hit), raw.get("query") or ""),
            resp_status=raw.get("resp_status"),
            src_port=raw.get("src_port"),
            query=raw.get("query") or None,
            user_agent=raw.get("user_agent"),
            headers=raw.get("headers") or {},
            payload=raw.get("payload") if raw.get("payload") is not None else raw.get("body", ""),
            raw=raw,
        )
    except NormalizationError:
        raise
    except Exception as exc:
        raise NormalizationError(f"unexpected shape: {exc}") from exc
