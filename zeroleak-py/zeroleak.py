#!/usr/bin/env python3
"""
ZeroLeak: Zero-Dependency Reversible PII & Secrets Sanitization Engine
=====================================================================
Ultra-fast, zero-external-dependency, reversible de-identification and
security sanitization proxy for autonomous AI agents and LLM gateways.

Integrates with ZeroMCP, HyperGate, and AgentTrace to ensure sensitive
real-world entities (PII, credentials, API keys) never cross network boundaries
while enabling complete post-inference and local tool restitution.

Standard Library Core: re, json, uuid, hashlib, secrets, dataclasses, typing, time, threading.
"""

import os
import sys
import re
import json
import time
import math
import uuid
import secrets
import hashlib
import threading
import argparse
import collections
import contextvars
import functools
import inspect
import bisect
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple, Set, Union, Callable

_TRACE_ID_CTX: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("zeroleak_trace_id", default=None)
_TOKEN_RE = re.compile(r"\[[A-Z0-9_]{1,32}_\d{1,9}\]")
_MAX_SCAN_CHARS = 2_000_000

def take_bounded_slice(payload: str, max_chars: int = _MAX_SCAN_CHARS) -> str:
    """Bounded stream slice preventing memory exhaustion from unbounded input frames."""
    return payload[:max_chars] if payload else ""

__version__ = "0.1.0"

# -----------------------------------------------------------------------------
# Configuration Constants & Environment Variables
# -----------------------------------------------------------------------------

ENV_MODE = "ZEROLEAK_MODE"                   # 'enforce' | 'observe'
ENV_ENTITIES = "ZEROLEAK_ENTITIES"           # Comma-separated list of entities
ENV_ALLOWLIST = "ZEROLEAK_ALLOWLIST"         # Comma-separated list of allowed domains/keys
ENV_VAULT_TTL = "ZEROLEAK_VAULT_TTL_SECONDS" # Default 1800 (30 minutes)
ENV_CUSTOM_RULES_PATH = "ZEROLEAK_CUSTOM_RULES_PATH" # Optional JSON path to enterprise rule definitions

DEFAULT_ENTITIES = [
    "EMAIL",
    "PHONE_US",
    "SSN",
    "CREDIT_CARD",
    "IP_ADDRESS",
    "API_KEY_HIGH_ENTROPY",
    "BEARER_TOKEN",
    "JWT",
    "CRYPTO_WALLET",
]

DEFAULT_ALLOWLIST = [
    "localhost",
    "127.0.0.1",
    "::1",
    "example.com",
    "test.com",
    "schema.org",
    "w3.org",
]


# -----------------------------------------------------------------------------
# Deterministic Mathematical Checksums & Entropy
# -----------------------------------------------------------------------------

def luhn_checksum(number_str: str) -> bool:
    """
    Validates a number string using the standard Luhn algorithm (mod-10).
    Used for credit cards (Visa, Mastercard, Amex, Discover, JCB, Diners).
    """
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def shannon_entropy(data: str) -> float:
    """
    Calculates Shannon entropy in bits per symbol: H = -sum(p * log2(p)).
    High-entropy keys (AWS, Stripe, random secrets) typically exhibit H >= 3.2.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_valid_ipv4(ip_str: str) -> bool:
    """Validates that each octet in an IPv4 address is an integer in 0..255."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
        # Disallow leading zeroes (e.g. 01.02.03.04) except single '0'
        if len(p) > 1 and p[0] == "0":
            return False
    return True


# -----------------------------------------------------------------------------
# Organization-Specific & Custom Entity Rules
# -----------------------------------------------------------------------------

@dataclass
class CustomEntityRule:
    """
    Organization-specific sensitive entity detection rule.
    Allows enterprises to define custom PII, internal IDs, proprietary tokens,
    or novel sensitive formats with optional validator callables and entropy thresholds.
    """
    name: str
    pattern: Union[str, re.Pattern]
    validator: Optional[Callable[[str], bool]] = None
    entropy_threshold: Optional[float] = None
    priority: int = 50
    description: str = ""

    def __post_init__(self):
        cleaned_name = str(self.name).strip().upper()
        if not re.match(r"^[A-Z0-9_]{1,32}$", cleaned_name):
            raise ValueError(
                f"Custom entity name '{self.name}' must be 1-32 uppercase alphanumeric/underscore characters (matching ^[A-Z0-9_]{{1,32}}$)."
            )
        self.name = cleaned_name

        if isinstance(self.pattern, str):
            try:
                self._compiled_re: re.Pattern = re.compile(self.pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern for custom entity rule '{self.name}': {e}")
        elif isinstance(self.pattern, re.Pattern):
            self._compiled_re = self.pattern
        else:
            raise TypeError(f"Rule pattern must be str or re.Pattern, got {type(self.pattern).__name__}")

        if self.entropy_threshold is not None:
            self.entropy_threshold = float(self.entropy_threshold)

        self.priority = int(self.priority)
        self.description = str(self.description or "")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CustomEntityRule":
        """Instantiates a CustomEntityRule from a dictionary specification."""
        name = data.get("name")
        pattern = data.get("pattern")
        if not name or not pattern:
            raise ValueError("Custom entity rule dictionary must provide 'name' and 'pattern'")

        val_spec = data.get("validator")
        validator_func: Optional[Callable[[str], bool]] = None
        if callable(val_spec):
            validator_func = val_spec
        elif isinstance(val_spec, str):
            val_lower = val_spec.strip().lower()
            if val_lower == "luhn":
                validator_func = luhn_checksum
            elif val_lower in ("ipv4", "ip"):
                validator_func = is_valid_ipv4
            else:
                raise ValueError(f"Unknown built-in validator name '{val_spec}'. Known validators: 'luhn', 'ipv4'.")

        return cls(
            name=str(name),
            pattern=pattern,
            validator=validator_func,
            entropy_threshold=data.get("entropy_threshold"),
            priority=data.get("priority", 50),
            description=data.get("description", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes rule to a clean JSON-serializable dictionary."""
        return {
            "name": self.name,
            "pattern": self._compiled_re.pattern,
            "entropy_threshold": self.entropy_threshold,
            "priority": self.priority,
            "description": self.description,
        }


# -----------------------------------------------------------------------------
# ReDoS-Immune Entity Detectors
# -----------------------------------------------------------------------------

# Pre-compiled atomic-style regexes avoiding catastrophic backtracking
PATTERNS: Dict[str, re.Pattern] = {
    # RFC 5322 simplified email with bounded length to prevent catastrophic backtracking
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b"
    ),

    # US Phone Numbers: E.164 (+1), (XXX) XXX-XXXX, XXX-XXX-XXXX, XXX.XXX.XXXX
    "PHONE_US": re.compile(
        r"(?:\+?1[-.\s]?)?\(?([2-9]\d{2})\)?[-.\s]?([2-9]\d{2})[-.\s]?(\d{4})\b"
    ),

    # US Social Security Number: XXX-XX-XXXX with invalid prefix rejection
    "SSN": re.compile(
        r"\b(?!000|666|9\d{2})(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b"
    ),

    # Credit Cards (13 to 19 digits formatted with spaces, dashes, or contiguous)
    # Validated strictly with Luhn algorithm
    "CREDIT_CARD": re.compile(
        r"\b(?:\d{4}[-\s]?){3}\d{1,7}\b|\b\d{13,19}\b"
    ),

    # IPv4 and IPv6 Addresses
    "IP_ADDRESS": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}\b"
    ),

    # Specific High-Value API Keys (AWS, GitHub, OpenAI, Stripe, Slack, Anthropic, Google)
    "API_KEY_KNOWN": re.compile(
        r"\bAKIA[0-9A-Z]{16}\b|"                                           # AWS Access Key
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|"              # GitHub PAT
        r"\bgithub_pat_[A-Za-z0-9_]{82}\b|"                               # GitHub fine-grained PAT
        r"\bsk-[a-zA-Z0-9_-]{20,}\b|"                                     # OpenAI / generic sk-
        r"\bsk-proj-[a-zA-Z0-9_-]{40,}\b|"                                # OpenAI project key
        r"\b[sr]k_(?:live|test)_[0-9a-zA-Z]{24,32}\b|"                     # Stripe secret/restricted key
        r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b|"        # Slack token
        r"\bAIza[0-9A-Za-z\-_]{35}\b|"                                    # Google API key
        r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b"                                  # Anthropic API key
    ),

    # Bearer Authentication Header Tokens
    "BEARER_TOKEN": re.compile(
        r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]+=*)"
    ),

    # JSON Web Tokens (JWT): header.payload.signature (bounded to prevent ReDoS)
    "JWT": re.compile(
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{10,1024}(?![A-Za-z0-9_-])"
    ),

    # Cryptocurrency Addresses (Ethereum 0x..., Bitcoin Legacy 1..., Segwit bc1...)
    "CRYPTO_WALLET": re.compile(
        r"\b0x[a-fA-F0-9]{40}\b|"
        r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|"
        r"\bbc1[a-z0-9]{39,59}\b"
    ),

    # Generic high-entropy secret token candidate (hex or base64 without spaces)
    "GENERIC_SECRET_CANDIDATE": re.compile(
        r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{24,4096}(?![A-Za-z0-9_\-])"
    ),
}

# Prompt Injection Markers for Inter-Agent Firewall
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|prompts|directives)\b"),
    re.compile(r"(?i)\b(?:system\s+directive|developer\s+mode|dan\s+mode)\b"),
    re.compile(r"(?i)<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]"),
    re.compile(r"(?i)\b(?:you\s+are\s+now|act\s+as\s+an?\s+unrestricted)\b"),
    re.compile(r"!\[[^\]]{0,512}\]\(\s*https?://[^\s)]{1,2048}\)"),  # Bounded markdown image exfiltration
    re.compile(r"[\u200b-\u200f\ufeff]"),           # Zero-width hiding vectors
    re.compile(r"\x1b\[[0-9;]*[a-zA-Z]"),           # ANSI escape sequences
]


# -----------------------------------------------------------------------------
# Ephemeral In-Memory Session Vault
# -----------------------------------------------------------------------------

@dataclass
class VaultEntry:
    token: str
    raw_value: str = field(repr=False)
    entity_type: str
    trace_id: str
    created_at: float
    last_accessed: float
    access_count: int = 0

    def touch(self):
        self.last_accessed = time.time()
        self.access_count += 1


class SessionVault:
    """
    Isolated, cryptographically salted session vault.
    Stores pairings between synthetic tokens and original raw values strictly in memory.
    Zero disk serialization. Auto-expiring sliding TTL per session.
    """
    MAX_SESSIONS = 10_000
    MAX_ENTRIES_PER_SESSION = int(os.getenv("ZEROLEAK_MAX_ENTRIES", "50000"))

    def __init__(self, default_ttl_seconds: int = 1800):
        self.default_ttl = max(1, int(default_ttl_seconds))
        self._lock = threading.RLock()
        self._salt = secrets.token_bytes(32)
        # trace_id -> {token -> VaultEntry}
        self._token_map: Dict[str, Dict[str, VaultEntry]] = {}
        # trace_id -> {salted_hash(raw_value) -> token}
        self._hash_map: Dict[str, Dict[str, str]] = {}
        # Counters for deterministic synthetic naming per session: trace_id -> {entity_type -> int}
        self._counters: Dict[str, Dict[str, int]] = {}
        # Last-accessed timestamps per trace_id for sliding TTL eviction
        self._session_created: Dict[str, float] = {}
        self._last_sweep: float = 0.0

    def _hash_val(self, raw_value: str) -> str:
        h = hashlib.sha256(self._salt)
        h.update(raw_value.encode("utf-8"))
        return h.hexdigest()

    def _evict_session(self, tid: str) -> None:
        self._token_map.pop(tid, None)
        self._hash_map.pop(tid, None)
        self._counters.pop(tid, None)
        self._session_created.pop(tid, None)

    def cleanup_expired(self, force: bool = True) -> int:
        """Evicts sessions that have exceeded the sliding TTL."""
        now = time.time()
        with self._lock:
            if not force and (now - self._last_sweep) < 30.0:
                return 0
            self._last_sweep = now
            expired_sessions = [
                tid for tid, last_ts in self._session_created.items()
                if now - last_ts > self.default_ttl
            ]
            for tid in expired_sessions:
                self._evict_session(tid)
            return len(expired_sessions)

    def get_or_create_token(
        self, trace_id: str, raw_value: str, entity_type: str
    ) -> str:
        """
        Retrieves existing token for raw_value in this session, or generates a new one.
        Ensures consistent co-reference (e.g. alice@acme.com always -> [EMAIL_1] within session).
        """
        with self._lock:
            self.cleanup_expired(force=False)
            now = time.time()

            if trace_id in self._session_created and (now - self._session_created[trace_id]) > self.default_ttl:
                self._evict_session(trace_id)

            if trace_id not in self._session_created:
                if len(self._session_created) >= self.MAX_SESSIONS:
                    oldest_tid = min(self._session_created, key=self._session_created.get)
                    self._evict_session(oldest_tid)
                self._token_map[trace_id] = {}
                self._hash_map[trace_id] = {}
                self._counters[trace_id] = collections.defaultdict(int)
            self._session_created[trace_id] = now

            hashed = self._hash_val(raw_value)
            existing_token = self._hash_map[trace_id].get(hashed)
            if existing_token:
                entry = self._token_map[trace_id][existing_token]
                entry.touch()
                return existing_token

            if len(self._token_map[trace_id]) >= self.MAX_ENTRIES_PER_SESSION:
                raise RuntimeError(f"ZeroLeak session {trace_id} exceeded max entries ({self.MAX_ENTRIES_PER_SESSION})")

            # Generate new deterministic type-aware synthetic token
            self._counters[trace_id][entity_type] += 1
            idx = self._counters[trace_id][entity_type]
            token = f"[{entity_type}_{idx}]"

            entry = VaultEntry(
                token=token,
                raw_value=raw_value,
                entity_type=entity_type,
                trace_id=trace_id,
                created_at=now,
                last_accessed=now,
                access_count=1,
            )
            self._token_map[trace_id][token] = entry
            self._hash_map[trace_id][hashed] = token
            return token

    def resolve_token(self, trace_id: str, token: str) -> Optional[str]:
        """Resolves synthetic token to original raw value."""
        with self._lock:
            session_tokens = self._token_map.get(trace_id)
            if not session_tokens:
                return None
            entry = session_tokens.get(token)
            if entry:
                entry.touch()
                return entry.raw_value
            return None

    def get_session_entries(self, trace_id: str) -> List[VaultEntry]:
        """Returns copies of vault entries for auditing (excluding internal salt)."""
        with self._lock:
            session_tokens = self._token_map.get(trace_id, {})
            return list(session_tokens.values())

    def touch(self, trace_id: str) -> bool:
        """Refreshes the sliding TTL timestamp for an active session."""
        with self._lock:
            if trace_id in self._session_created:
                self._session_created[trace_id] = time.time()
                return True
            return False

    def purge(self, trace_id: str) -> bool:
        """Explicitly wipes a session from memory immediately."""
        with self._lock:
            p1 = self._token_map.pop(trace_id, None) is not None
            self._hash_map.pop(trace_id, None)
            self._counters.pop(trace_id, None)
            self._session_created.pop(trace_id, None)
            return p1

    def __repr__(self) -> str:
        # Anti-leak invariant: Never expose internal dictionary or salt in representations
        with self._lock:
            session_count = len(self._token_map)
            total_tokens = sum(len(m) for m in self._token_map.values())
        return f"<SessionVault sessions={session_count} active_tokens={total_tokens} storage=RAM_ONLY>"


# -----------------------------------------------------------------------------
# Audit Telemetry & Receipts
# -----------------------------------------------------------------------------

@dataclass
class AuditReceipt:
    trace_id: str
    mode: str
    masked_count: int
    restituted_count: int
    types_detected: Dict[str, int]
    advisories: List[str]
    duration_ms: float
    zero_disk_leakage: bool = True
    timestamp: str = field(default_factory=lambda: datetime_datetime_now())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def datetime_datetime_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# -----------------------------------------------------------------------------
# ZeroLeak Core Engine
# -----------------------------------------------------------------------------

class ZeroLeak:
    """
    Zero-dependency de-identification and security sanitization engine.
    Supports 'enforce' (active substitution) and 'observe' (advisory) modes.
    """
    def __init__(
        self,
        mode: Optional[str] = None,
        enabled_entities: Optional[List[str]] = None,
        allowlist: Optional[List[str]] = None,
        vault_ttl_seconds: Optional[int] = None,
        custom_rules: Optional[List[Union[CustomEntityRule, Dict[str, Any]]]] = None,
    ):
        self.mode = mode or os.getenv(ENV_MODE, "enforce").strip().lower()
        if self.mode not in ("enforce", "observe"):
            self.mode = "enforce"

        # Entity selection
        env_entities = os.getenv(ENV_ENTITIES)
        if enabled_entities:
            self.enabled_entities = set(enabled_entities)
        elif env_entities:
            self.enabled_entities = {e.strip() for e in env_entities.split(",") if e.strip()}
        else:
            self.enabled_entities = set(DEFAULT_ENTITIES)

        # Allowlist selection
        env_allowlist = os.getenv(ENV_ALLOWLIST)
        if allowlist is not None:
            self.allowlist = set(allowlist)
        elif env_allowlist:
            self.allowlist = {a.strip().lower() for a in env_allowlist.split(",") if a.strip()}
        else:
            self.allowlist = set(DEFAULT_ALLOWLIST)

        # Vault TTL
        ttl = vault_ttl_seconds or int(os.getenv(ENV_VAULT_TTL, "1800"))
        self.vault = SessionVault(default_ttl_seconds=ttl)

        # Execution receipts cache: trace_id -> AuditReceipt (Bounded LRU)
        self.MAX_RECEIPTS = 10_000
        self._receipts: collections.OrderedDict[str, AuditReceipt] = collections.OrderedDict()
        self._lock = threading.RLock()

        # Custom organizational rules: name -> CustomEntityRule
        self._custom_rules: Dict[str, CustomEntityRule] = {}
        if custom_rules:
            for r in custom_rules:
                self.register_custom_rule(r)

        env_custom_rules_path = os.getenv(ENV_CUSTOM_RULES_PATH)
        if env_custom_rules_path and os.path.isfile(env_custom_rules_path):
            self.register_rules_from_json(env_custom_rules_path)

    def register_custom_rule(self, rule: Union[CustomEntityRule, Dict[str, Any]]) -> "ZeroLeak":
        """
        Registers an organization-specific entity rule.
        Accepts either a CustomEntityRule instance or a dictionary specification.
        Automatically enables the custom entity name in the active detection set.
        """
        if isinstance(rule, dict):
            rule_obj = CustomEntityRule.from_dict(rule)
        elif isinstance(rule, CustomEntityRule):
            rule_obj = rule
        else:
            raise TypeError(f"Expected CustomEntityRule or dict, got {type(rule).__name__}")

        with self._lock:
            self._custom_rules[rule_obj.name] = rule_obj
            self.enabled_entities.add(rule_obj.name)
        return self

    def register_rules_from_dict(self, rules_data: Union[List[Dict[str, Any]], Dict[str, Any]]) -> "ZeroLeak":
        """
        Batch registers custom rules from a list of dicts or a mapping structure.
        Supports {"rules": [...]} or [{"name": ...}] or {"NAME": {"pattern": ...}}.
        """
        items: List[Dict[str, Any]] = []
        if isinstance(rules_data, dict):
            if "rules" in rules_data and isinstance(rules_data["rules"], list):
                items = rules_data["rules"]
            else:
                for k, v in rules_data.items():
                    if isinstance(v, dict):
                        d = dict(v)
                        d.setdefault("name", k)
                        items.append(d)
        elif isinstance(rules_data, list):
            items = rules_data
        else:
            raise TypeError("rules_data must be a list of rule dicts or a dictionary")

        for item in items:
            self.register_custom_rule(item)
        return self

    def register_rules_from_json(self, json_str_or_filepath: str) -> "ZeroLeak":
        """Loads and registers custom entity rules from a JSON file path or raw JSON string."""
        path_str = str(json_str_or_filepath)
        if os.path.isfile(path_str):
            with open(path_str, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = json.loads(path_str)
        return self.register_rules_from_dict(data)

    def unregister_custom_rule(self, name: str) -> bool:
        """Removes a custom entity rule by name."""
        cleaned = str(name).strip().upper()
        with self._lock:
            removed = self._custom_rules.pop(cleaned, None) is not None
            self.enabled_entities.discard(cleaned)
            return removed

    def get_custom_rules(self) -> List[CustomEntityRule]:
        """Returns a snapshot list of currently registered custom rules."""
        with self._lock:
            return list(self._custom_rules.values())

    def _record_receipt(self, trace_id: str, receipt: AuditReceipt):
        with self._lock:
            if trace_id in self._receipts:
                self._receipts.move_to_end(trace_id)
            self._receipts[trace_id] = receipt
            if len(self._receipts) > self.MAX_RECEIPTS:
                self._receipts.popitem(last=False)

    def is_allowed(self, value: str, entity_type: str = "") -> bool:
        """Checks whether an entity value matches an item in the allowlist (fail-closed for credentials)."""
        if not self.allowlist:
            return False
        lowered = value.strip().lower()
        if entity_type in ("API_KEY", "BEARER_TOKEN", "JWT", "CRYPTO_KEY", "PRIVATE_KEY"):
            return False
        if entity_type == "EMAIL" and "@" in lowered:
            dom = lowered.rsplit("@", 1)[-1]
            return any(lowered == a or dom == a or dom.endswith("." + a) for a in self.allowlist if a)
        if entity_type == "IP_ADDRESS":
            return any(lowered == a for a in self.allowlist if a)
        return any(lowered == a for a in self.allowlist if a)

    def scan_entities(self, text: str) -> List[Tuple[int, int, str, str]]:
        """
        Scans text for sensitive entities using compiled regexes, Luhn, Shannon entropy,
        and custom organizational rules.
        Returns a sorted list of non-overlapping (start_idx, end_idx, entity_type, raw_value).
        """
        candidates: List[Tuple[int, int, str, str, int]] = []
        BUILTIN_PRIO = 10

        # 1. EMAIL
        if "EMAIL" in self.enabled_entities:
            for m in PATTERNS["EMAIL"].finditer(text):
                val = m.group(0)
                if not self.is_allowed(val, "EMAIL"):
                    candidates.append((m.start(), m.end(), "EMAIL", val, BUILTIN_PRIO))

        # 2. PHONE_US
        if "PHONE_US" in self.enabled_entities:
            for m in PATTERNS["PHONE_US"].finditer(text):
                val = m.group(0)
                if not self.is_allowed(val, "PHONE"):
                    candidates.append((m.start(), m.end(), "PHONE", val, BUILTIN_PRIO))

        # 3. SSN
        if "SSN" in self.enabled_entities:
            for m in PATTERNS["SSN"].finditer(text):
                val = m.group(0)
                if not self.is_allowed(val, "SSN"):
                    candidates.append((m.start(), m.end(), "SSN", val, BUILTIN_PRIO))

        # 4. CREDIT_CARD (Validated by Luhn algorithm)
        if "CREDIT_CARD" in self.enabled_entities:
            for m in PATTERNS["CREDIT_CARD"].finditer(text):
                val = m.group(0)
                digits = re.sub(r"\D", "", val)
                if 13 <= len(digits) <= 19 and luhn_checksum(digits):
                    if not self.is_allowed(val, "CREDIT_CARD"):
                        candidates.append((m.start(), m.end(), "CREDIT_CARD", val, BUILTIN_PRIO))

        # 5. IP_ADDRESS
        if "IP_ADDRESS" in self.enabled_entities:
            for m in PATTERNS["IP_ADDRESS"].finditer(text):
                val = m.group(0)
                if not self.is_allowed(val, "IP_ADDRESS"):
                    # For IPv4, verify octets <= 255
                    if "." in val and not is_valid_ipv4(val):
                        continue
                    candidates.append((m.start(), m.end(), "IP_ADDRESS", val, BUILTIN_PRIO))

        # 6. KNOWN API KEYS
        if "API_KEY_HIGH_ENTROPY" in self.enabled_entities:
            for m in PATTERNS["API_KEY_KNOWN"].finditer(text):
                val = m.group(0)
                if not self.is_allowed(val, "API_KEY"):
                    candidates.append((m.start(), m.end(), "API_KEY", val, BUILTIN_PRIO))

        # 7. BEARER TOKENS
        if "BEARER_TOKEN" in self.enabled_entities:
            for m in PATTERNS["BEARER_TOKEN"].finditer(text):
                val = m.group(1)
                if len(val) >= 16 and not self.is_allowed(val, "BEARER_TOKEN"):
                    candidates.append((m.start(1), m.end(1), "BEARER_TOKEN", val, BUILTIN_PRIO))

        # 8. JWT
        if "JWT" in self.enabled_entities:
            for m in PATTERNS["JWT"].finditer(text):
                val = m.group(0)
                if not self.is_allowed(val, "JWT"):
                    candidates.append((m.start(), m.end(), "JWT", val, BUILTIN_PRIO))

        # 9. CRYPTO WALLET
        if "CRYPTO_WALLET" in self.enabled_entities:
            for m in PATTERNS["CRYPTO_WALLET"].finditer(text):
                val = m.group(0)
                if not self.is_allowed(val, "CRYPTO_KEY"):
                    candidates.append((m.start(), m.end(), "CRYPTO_KEY", val, BUILTIN_PRIO))

        # 10. GENERIC HIGH-ENTROPY SECRETS
        if "API_KEY_HIGH_ENTROPY" in self.enabled_entities:
            for m in PATTERNS["GENERIC_SECRET_CANDIDATE"].finditer(text):
                val = m.group(0)
                if len(val) >= 30 and not self.is_allowed(val, "API_KEY"):
                    entropy = shannon_entropy(val)
                    if entropy >= 3.3:
                        candidates.append((m.start(), m.end(), "API_KEY", val, BUILTIN_PRIO))

        # 11. Custom Organizational & Novel Rules
        with self._lock:
            custom_rules_snapshot = list(self._custom_rules.values())

        for rule in custom_rules_snapshot:
            if rule.name not in self.enabled_entities:
                continue
            for m in rule._compiled_re.finditer(text):
                val = m.group(0)
                if not val or self.is_allowed(val, rule.name):
                    continue
                # Optional programmatic validator callback
                if rule.validator and not rule.validator(val):
                    continue
                # Optional Shannon entropy check
                if rule.entropy_threshold is not None:
                    if shannon_entropy(val) < rule.entropy_threshold:
                        continue
                candidates.append((m.start(), m.end(), rule.name, val, rule.priority))

        # Sort candidates: higher priority first, then earlier start, then longer match
        candidates.sort(key=lambda x: (-x[4], x[0], -(x[1] - x[0])))

        # Fast non-overlapping interval selection by priority via bisect search O(M log M)
        selected: List[Tuple[int, int, str, str]] = []
        occupied_spans: List[Tuple[int, int]] = []

        for start, end, etype, val, prio in candidates:
            idx = bisect.bisect_right(occupied_spans, (start, float("inf")))
            overlaps = False
            if idx > 0 and occupied_spans[idx - 1][1] > start:
                overlaps = True
            elif idx < len(occupied_spans) and occupied_spans[idx][0] < end:
                overlaps = True

            if not overlaps:
                selected.append((start, end, etype, val))
                bisect.insort(occupied_spans, (start, end))

        # Re-sort selected matches in text stream order
        selected.sort(key=lambda x: x[0])
        return selected

    def mask(self, text: str, trace_id: Optional[str] = None) -> str:
        """
        Pre-inference reversible tokenization.
        Replaces sensitive entities with synthetic tokens.
        In 'observe' mode, logs what would be masked without altering the text.
        """
        t0 = time.perf_counter()
        trace_id = trace_id or f"trc_{uuid.uuid4().hex[:12]}"
        matches = self.scan_entities(text)

        types_detected: Dict[str, int] = collections.defaultdict(int)
        advisories: List[str] = []

        if not matches:
            receipt = AuditReceipt(
                trace_id=trace_id,
                mode=self.mode,
                masked_count=0,
                restituted_count=0,
                types_detected={},
                advisories=[],
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )
            self._record_receipt(trace_id, receipt)
            return text

        # Handle 'observe' mode
        if self.mode == "observe":
            for _, _, etype, val in matches:
                types_detected[etype] += 1
                advisories.append(f"[ZeroLeak OBSERVE] Would mask {etype}: '{val[:3]}...{val[-3:] if len(val) > 6 else ''}'")
            receipt = AuditReceipt(
                trace_id=trace_id,
                mode=self.mode,
                masked_count=0,
                restituted_count=0,
                types_detected=dict(types_detected),
                advisories=advisories,
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )
            self._record_receipt(trace_id, receipt)
            return text

        # Handle 'enforce' mode: rebuild text with synthetic tokens from right to left
        result_chunks = []
        last_idx = 0
        for start, end, etype, val in matches:
            types_detected[etype] += 1
            result_chunks.append(text[last_idx:start])
            token = self.vault.get_or_create_token(trace_id, val, etype)
            result_chunks.append(token)
            last_idx = end
        result_chunks.append(text[last_idx:])

        sanitized_text = "".join(result_chunks)

        receipt = AuditReceipt(
            trace_id=trace_id,
            mode=self.mode,
            masked_count=len(matches),
            restituted_count=0,
            types_detected=dict(types_detected),
            advisories=advisories,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
        self._record_receipt(trace_id, receipt)

        return sanitized_text

    def unmask(self, text: str, trace_id: str) -> str:
        """
        Post-inference restitution in a single O(n) pass.
        Restores synthetic tokens back to original raw values from the ephemeral vault.
        """
        t0 = time.perf_counter()
        session_entries = self.vault.get_session_entries(trace_id)
        if not session_entries:
            return text

        self.vault.touch(trace_id)
        entry_map = {e.token: e for e in session_entries}
        restituted_count = 0

        def _replace(match: re.Match) -> str:
            nonlocal restituted_count
            tok = match.group(0)
            entry = entry_map.get(tok)
            if entry is not None:
                entry.touch()
                restituted_count += 1
                return entry.raw_value
            return tok

        restituted_text = _TOKEN_RE.sub(_replace, text)

        # Update receipt
        with self._lock:
            receipt = self._receipts.get(trace_id)
            if receipt:
                receipt.restituted_count += restituted_count
                receipt.duration_ms += (time.perf_counter() - t0) * 1000.0

        return restituted_text

    def touch(self, trace_id: str) -> bool:
        """Refreshes the in-memory sliding TTL for a given session."""
        return self.vault.touch(trace_id)

    def mask_object(self, obj: Any, trace_id: Optional[str] = None, _depth: int = 0) -> Any:
        """Recursively masks strings and dict keys inside arbitrary dicts, lists, or primitives."""
        if _depth > 32:
            raise ValueError("ZeroLeak mask_object max recursion depth (32) exceeded")
        tid = trace_id or f"trc_{uuid.uuid4().hex[:12]}"
        if isinstance(obj, str):
            return self.mask(obj, trace_id=tid)
        elif isinstance(obj, dict):
            return {
                (self.mask(k, trace_id=tid) if isinstance(k, str) else k): self.mask_object(v, trace_id=tid, _depth=_depth + 1)
                for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [self.mask_object(item, trace_id=tid, _depth=_depth + 1) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self.mask_object(item, trace_id=tid, _depth=_depth + 1) for item in obj)
        return obj

    def unmask_object(self, obj: Any, trace_id: str, _depth: int = 0) -> Any:
        """Recursively unmasks synthetic tokens inside arbitrary dicts, lists, or primitives."""
        if _depth > 32:
            raise ValueError("ZeroLeak unmask_object max recursion depth (32) exceeded")
        if isinstance(obj, str):
            return self.unmask(obj, trace_id=trace_id)
        elif isinstance(obj, dict):
            return {k: self.unmask_object(v, trace_id=trace_id, _depth=_depth + 1) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.unmask_object(item, trace_id=trace_id, _depth=_depth + 1) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self.unmask_object(item, trace_id=trace_id, _depth=_depth + 1) for item in obj)
        return obj

    def sanitize_tool_output(self, content: str) -> str:
        """
        Inter-Agent Prompt-Injection Firewall:
        Neutralizes indirect prompt injection payloads without echoing raw snippets.
        """
        sanitized = content
        for pat in PROMPT_INJECTION_PATTERNS:
            sanitized = pat.sub("[DEFANGED_INJECTION]", sanitized)
        return sanitized

    def _sanitize_object(self, obj: Any, _depth: int = 0) -> Any:
        if _depth > 32:
            return obj
        if isinstance(obj, str):
            return self.sanitize_tool_output(obj)
        elif isinstance(obj, dict):
            return {k: self._sanitize_object(v, _depth + 1) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._sanitize_object(item, _depth + 1) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self._sanitize_object(item, _depth + 1) for item in obj)
        return obj

    def protect_tool(self, handler: Callable[..., Any]) -> Callable[..., Any]:
        """
        ZeroMCP middleware decorator wrapper.
        Ensures local tool receives restituted parameters while external LLM only sees masked tokens.
        Also sanitizes and re-masks outgoing tool responses (sync and async).
        """
        def _resolve_trace_id(kwargs: dict) -> str:
            ctx_tid = _TRACE_ID_CTX.get()
            if ctx_tid:
                kwargs.pop("_trace_id", None)
                return ctx_tid
            return kwargs.pop("_trace_id", None) or os.getenv("ZEROLEAK_CURRENT_TRACE_ID") or f"trc_{uuid.uuid4().hex[:12]}"

        if inspect.iscoroutinefunction(handler):
            @functools.wraps(handler)
            async def async_wrapped(*args, **kwargs):
                trace_id = _resolve_trace_id(kwargs)
                safe_args = [self.unmask_object(arg, trace_id) for arg in args]
                safe_kwargs = {k: self.unmask_object(v, trace_id) for k, v in kwargs.items()}
                result = await handler(*safe_args, **safe_kwargs)
                result = self._sanitize_object(result)
                return self.mask_object(result, trace_id=trace_id)
            return async_wrapped

        @functools.wraps(handler)
        def wrapped(*args, **kwargs):
            trace_id = _resolve_trace_id(kwargs)
            safe_args = [self.unmask_object(arg, trace_id) for arg in args]
            safe_kwargs = {k: self.unmask_object(v, trace_id) for k, v in kwargs.items()}
            result = handler(*safe_args, **safe_kwargs)
            result = self._sanitize_object(result)
            return self.mask_object(result, trace_id=trace_id)
        return wrapped

    def get_audit_receipt(self, trace_id: str) -> Optional[AuditReceipt]:
        with self._lock:
            return self._receipts.get(trace_id)

    def print_audit_receipt(self, trace_id: str):
        """Prints a human-readable compliance audit receipt."""
        receipt = self.get_audit_receipt(trace_id)
        if not receipt:
            print(f"⚠️ [ZeroLeak] No audit receipt found for trace_id: {trace_id}")
            return

        print("\n" + "=" * 65)
        print("          ZEROLEAK SECURITY & COMPLIANCE AUDIT RECEIPT")
        print("=" * 65)
        print(f" Trace ID:             {receipt.trace_id}")
        print(f" Execution Mode:       {receipt.mode.upper()}")
        print(f" Timestamp:            {receipt.timestamp}")
        print(f" Masked Entities:      {receipt.masked_count}")
        print(f" Restituted Tokens:    {receipt.restituted_count}")
        print(f" Processing Time:      {receipt.duration_ms:.2f} ms")
        print(f" Ephemeral Storage:    {'RAM ONLY (Zero Disk Writes)' if receipt.zero_disk_leakage else 'PERSISTED'}")
        print("-" * 65)
        print(" Entity Breakdown:")
        if receipt.types_detected:
            for k, v in receipt.types_detected.items():
                print(f"   • {k:<20}: {v}")
        else:
            print("   • (No sensitive entities detected)")

        if receipt.advisories:
            print("-" * 65)
            print(" Observability Advisories:")
            for adv in receipt.advisories:
                print(f"   {adv}")
        print("=" * 65 + "\n")


# Global singleton instance for convenient import
default_engine = ZeroLeak()

def mask(text: str, trace_id: Optional[str] = None) -> str:
    return default_engine.mask(text, trace_id=trace_id)

def unmask(text: str, trace_id: str) -> str:
    return default_engine.unmask(text, trace_id=trace_id)

def protect_tool(handler: Callable[..., Any]) -> Callable[..., Any]:
    return default_engine.protect_tool(handler)

def print_audit_receipt(trace_id: str):
    default_engine.print_audit_receipt(trace_id)

def register_custom_rule(rule: Union[CustomEntityRule, Dict[str, Any]]) -> ZeroLeak:
    return default_engine.register_custom_rule(rule)

def register_rules_from_dict(rules_data: Union[List[Dict[str, Any]], Dict[str, Any]]) -> ZeroLeak:
    return default_engine.register_rules_from_dict(rules_data)

def register_rules_from_json(json_str_or_filepath: str) -> ZeroLeak:
    return default_engine.register_rules_from_json(json_str_or_filepath)

def get_custom_rules() -> List[CustomEntityRule]:
    return default_engine.get_custom_rules()


# -----------------------------------------------------------------------------
# Developer Ergonomics & CLI Quick-Test
# -----------------------------------------------------------------------------

def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ZeroLeak: Zero-Dependency Reversible PII & Secrets Sanitization Engine"
    )
    parser.add_argument("--test", type=str, help="Quick-test string with PII/secrets to mask and restitute")
    parser.add_argument("--mode", choices=["enforce", "observe"], default=None, help="Execution mode")
    parser.add_argument("--custom-rules-file", type=str, help="Path to JSON file with custom organizational entity rules")
    parser.add_argument("--list-entities", action="store_true", help="List all supported entity detectors")
    parser.add_argument("--print-config", action="store_true", help="Print active configuration & environment bindings")
    parser.add_argument("--firewall-test", type=str, help="Test prompt-injection firewall on untrusted input")
    return parser


def main():
    parser = build_cli_parser()
    args = parser.parse_args()

    engine = ZeroLeak(mode=args.mode) if args.mode else default_engine
    if args.custom_rules_file:
        engine.register_rules_from_json(args.custom_rules_file)

    if args.list_entities:
        print("\nSupported ZeroLeak Built-in Detectors:")
        for entity in DEFAULT_ENTITIES:
            print(f"  • {entity}")
        customs = engine.get_custom_rules()
        if customs:
            print("\nRegistered Custom Organizational Rules:")
            for cr in customs:
                desc = f" ({cr.description})" if cr.description else ""
                print(f"  • {cr.name} [priority={cr.priority}]{desc}")
        print("\nDefault Allowlist:")
        for allow in DEFAULT_ALLOWLIST:
            print(f"  • {allow}")
        return

    if args.print_config:
        print("\nZeroLeak Runtime Configuration:")
        print(f"  • Version:         {__version__}")
        print(f"  • Mode:            {engine.mode}")
        print(f"  • Active Entities: {', '.join(sorted(engine.enabled_entities))}")
        print(f"  • Custom Rules:    {len(engine.get_custom_rules())}")
        print(f"  • Allowlist Count: {len(engine.allowlist)}")
        print(f"  • Vault TTL:       {engine.vault.default_ttl}s")
        print(f"  • Ephemeral Vault: {engine.vault}")
        return

    if args.firewall_test:
        print("\nTesting Inter-Agent Prompt Injection Firewall:")
        print(f"Original Input:\n  {args.firewall_test}")
        sanitized = engine.sanitize_tool_output(args.firewall_test)
        print(f"\nSanitized Output:\n  {sanitized}\n")
        return

    if args.test:
        test_text = args.test
        trace_id = f"test_{uuid.uuid4().hex[:8]}"
        print(f"\n--- [ZeroLeak Quick-Test] (Trace: {trace_id}) ---")
        print(f"Original Plaintext:\n  {test_text}\n")

        masked_text = engine.mask(test_text, trace_id=trace_id)
        print(f"Masked (Safe for LLM Boundary):\n  {masked_text}\n")

        session_entries = engine.vault.get_session_entries(trace_id)
        print(f"Ephemeral Session Vault ({len(session_entries)} tokens captured in RAM):")
        for entry in session_entries:
            print(f"  • {entry.token} -> {entry.raw_value} ({entry.entity_type})")

        restituted_text = engine.unmask(masked_text, trace_id=trace_id)
        print(f"\nRestituted Plaintext:\n  {restituted_text}\n")

        fidelity = (test_text == restituted_text)
        print(f"100% Roundtrip Fidelity: {'✅ PASS' if fidelity else '❌ FAIL'}")

        engine.print_audit_receipt(trace_id)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
