"""Mechanical, rule-based detectors.

These are deterministic producers, not agents. Each rule maps an observable
pattern to a *specific* structured claim, and every claim it emits points at
the exact string or symbol artifact that triggered it. A reviewer can always
walk from the claim back to the bytes.

Two deliberate limits on what these rules are allowed to say:

* ``uses_risky_api`` is an attack-surface indicator. Referencing ``strcpy`` is
  not a vulnerability, and the predicate's own documentation says so. Nothing
  here asserts exploitability.
* Confidence values are calibrated to the *rule*, not to the target. A pattern
  with a rigid, unmistakable shape (an AWS key id, a PEM header) scores high; a
  loose keyword match scores low and is expected to need corroboration.

The lists are intentionally short and curated. A detector that fires on
``printf`` in every binary on earth costs precision and buys nothing, so it is
not here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Iterator

from aether.util import redact


@dataclass(frozen=True)
class SecretRule:
    """A pattern whose match is credential-shaped."""

    rule_id: str
    secret_kind: str
    pattern: re.Pattern[str]
    confidence: float
    description: str


@dataclass(frozen=True)
class Detection:
    """One rule firing on one piece of text."""

    rule_id: str
    kind: str
    matched: str
    start: int
    confidence: float
    extra: dict[str, str]


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "aws-access-key-id",
        "aws_access_key",
        re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA)[A-Z0-9]{16})\b"),
        0.95,
        "AWS access key identifier",
    ),
    SecretRule(
        "pem-private-key",
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        0.98,
        "PEM-encoded private key header",
    ),
    SecretRule(
        "pem-certificate",
        "certificate",
        re.compile(r"-----BEGIN CERTIFICATE-----"),
        0.95,
        "PEM-encoded X.509 certificate",
    ),
    SecretRule(
        "ssh-authorized-key",
        "ssh_authorized_key",
        re.compile(r"\bssh-(?:rsa|ed25519|dss)\s+AAAA[0-9A-Za-z+/]{20,}"),
        0.9,
        "OpenSSH public key in authorized_keys form",
    ),
    SecretRule(
        "jwt",
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        0.85,
        "JSON Web Token",
    ),
    SecretRule(
        "github-token",
        "api_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
        0.95,
        "GitHub personal access token",
    ),
    SecretRule(
        "slack-token",
        "api_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
        0.9,
        "Slack API token",
    ),
    SecretRule(
        "connection-string-credentials",
        "connection_string",
        re.compile(
            r"\b(?:mysql|postgresql|postgres|mongodb\+srv|mongodb|redis|amqp|ftp)"
            r"://[^\s:@/]{1,64}:[^\s:@/]{1,64}@[^\s/]{1,128}"
        ),
        0.9,
        "URI carrying inline credentials",
    ),
    SecretRule(
        "private-key-body",
        "private_key",
        re.compile(r"\bMII[A-Za-z0-9+/]{40,}"),
        0.6,
        "DER/base64 key material, unlabelled",
    ),
    SecretRule(
        "assigned-credential",
        "password",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|secret|auth[_-]?token|access[_-]?token|"
            r"passwd|password|pwd)\b\s*[:=]\s*[\"']?([A-Za-z0-9_@#!$%^&*.\-]{8,})"
        ),
        0.45,
        "Credential-shaped assignment; loose pattern, expect false positives",
    ),
)


#: Symbol name -> (predicate category, base confidence).
#: Presence of the symbol is a fact; the *category* is the editorial judgment,
#: and it is the only judgment these rules make.
RISKY_APIS: dict[str, tuple[str, float]] = {
    # Unbounded copies into fixed buffers.
    "strcpy": ("memory_copy", 0.9),
    "strcat": ("memory_copy", 0.9),
    "stpcpy": ("memory_copy", 0.85),
    "wcscpy": ("memory_copy", 0.85),
    "lstrcpyA": ("memory_copy", 0.85),
    "lstrcatA": ("memory_copy", 0.85),
    "gets": ("memory_copy", 0.98),
    "sprintf": ("memory_copy", 0.9),
    "vsprintf": ("memory_copy", 0.9),
    "scanf": ("memory_copy", 0.7),
    "sscanf": ("memory_copy", 0.6),
    "alloca": ("memory_copy", 0.6),
    # Shell and process execution reachable from data.
    "system": ("command_exec", 0.9),
    "popen": ("command_exec", 0.9),
    "execl": ("command_exec", 0.8),
    "execlp": ("command_exec", 0.85),
    "execv": ("command_exec", 0.8),
    "execvp": ("command_exec", 0.85),
    "execve": ("command_exec", 0.75),
    "WinExec": ("command_exec", 0.9),
    "ShellExecuteA": ("command_exec", 0.85),
    "ShellExecuteW": ("command_exec", 0.85),
    "CreateProcessA": ("command_exec", 0.7),
    "_wsystem": ("command_exec", 0.9),
    # Format strings that routinely take a non-literal format.
    "syslog": ("format_string", 0.6),
    "vfprintf": ("format_string", 0.5),
    "vprintf": ("format_string", 0.5),
    # Cryptography that should not appear in new designs.
    "MD5_Init": ("weak_crypto", 0.85),
    "MD5_Update": ("weak_crypto", 0.85),
    "SHA1_Init": ("weak_crypto", 0.7),
    "DES_set_key": ("weak_crypto", 0.9),
    "DES_ecb_encrypt": ("weak_crypto", 0.9),
    "RC4": ("weak_crypto", 0.9),
    "EVP_des_ecb": ("weak_crypto", 0.9),
    "EVP_rc4": ("weak_crypto", 0.9),
    # Predictable randomness, which matters when it seeds anything security-bearing.
    "rand": ("weak_random", 0.6),
    "srand": ("weak_random", 0.6),
    "random": ("weak_random", 0.5),
    "srandom": ("weak_random", 0.5),
    # Privilege transitions.
    "setuid": ("privilege", 0.7),
    "setgid": ("privilege", 0.7),
    "seteuid": ("privilege", 0.7),
    "setresuid": ("privilege", 0.7),
    # Deserialization of untrusted structure.
    "unserialize": ("unsafe_deserialization", 0.7),
    "pickle_loads": ("unsafe_deserialization", 0.7),
}


@dataclass(frozen=True)
class ComponentRule:
    """A version banner that identifies an embedded third-party component."""

    component: str
    pattern: re.Pattern[str]
    confidence: float


COMPONENT_RULES: tuple[ComponentRule, ...] = (
    ComponentRule("busybox", re.compile(r"BusyBox v([0-9]+\.[0-9]+\.[0-9]+)"), 0.95),
    ComponentRule("openssl", re.compile(r"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)"), 0.95),
    ComponentRule("dropbear", re.compile(r"[Dd]ropbear[ _]v?([0-9]+\.[0-9]+)"), 0.9),
    ComponentRule("zlib", re.compile(r"(?:in|de)flate ([0-9]+\.[0-9.]+) Copyright"), 0.9),
    ComponentRule("lighttpd", re.compile(r"lighttpd/([0-9]+\.[0-9.]+)"), 0.9),
    ComponentRule("libcurl", re.compile(r"libcurl/([0-9]+\.[0-9.]+)"), 0.9),
    ComponentRule("uclibc", re.compile(r"uClibc(?:-ng)? ([0-9]+\.[0-9.]+)"), 0.9),
    ComponentRule("linux_kernel", re.compile(r"Linux version ([0-9]+\.[0-9][0-9.]*)"), 0.9),
    ComponentRule("gcc", re.compile(r"GCC: \([^)]*\) ([0-9]+\.[0-9.]+)"), 0.85),
    ComponentRule("mbedtls", re.compile(r"mbed ?TLS ([0-9]+\.[0-9.]+)"), 0.9),
    ComponentRule("wolfssl", re.compile(r"wolfSSL ([0-9]+\.[0-9.]+)"), 0.9),
    ComponentRule("openssh", re.compile(r"OpenSSH_([0-9]+\.[0-9][0-9a-z.]*)"), 0.9),
    ComponentRule("sqlite", re.compile(r"SQLite version ([0-9]+\.[0-9.]+)"), 0.9),
    ComponentRule("u_boot", re.compile(r"U-Boot ([0-9]{4}\.[0-9]{2})"), 0.9),
)


def scan_secrets(text: str) -> Iterator[Detection]:
    """Yield credential-shaped matches in ``text``.

    The matched literal is redacted before it leaves this function: claims
    carry a masked preview, and the full value stays in the string artifact
    where access is at least deliberate.
    """
    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            captured = match.group(1) if match.groups() else match.group(0)
            yield Detection(
                rule_id=rule.rule_id,
                kind=rule.secret_kind,
                matched=redact(captured),
                start=match.start(),
                confidence=rule.confidence,
                extra={"description": rule.description},
            )


def scan_components(text: str) -> Iterator[Detection]:
    """Yield third-party component banners found in ``text``."""
    for rule in COMPONENT_RULES:
        for match in rule.pattern.finditer(text):
            yield Detection(
                rule_id=f"component:{rule.component}",
                kind=rule.component,
                matched=match.group(0),
                start=match.start(),
                confidence=rule.confidence,
                extra={"version": match.group(1) if match.groups() else ""},
            )


def classify_symbol(name: str) -> tuple[str, float] | None:
    """Return ``(category, confidence)`` when ``name`` is a risky API.

    Handles the decorations real symbol tables carry: a leading underscore, a
    glibc versioned alias, an IAT thunk prefix.
    """
    candidates = [name]
    stripped = name.lstrip("_")
    if stripped != name:
        candidates.append(stripped)
    if "@" in name:
        candidates.append(name.split("@", 1)[0].lstrip("_"))
    for prefix in ("__isoc99_", "__builtin_", "imp_", "__imp_"):
        for candidate in list(candidates):
            if candidate.startswith(prefix):
                candidates.append(candidate[len(prefix) :])
    for candidate in candidates:
        hit = RISKY_APIS.get(candidate)
        if hit:
            return hit
    return None


def classify_symbols(names: Iterable[str]) -> dict[str, tuple[str, float]]:
    """Classify many symbols at once, keeping only the risky ones."""
    out: dict[str, tuple[str, float]] = {}
    for name in names:
        hit = classify_symbol(name)
        if hit:
            out[name] = hit
    return out
