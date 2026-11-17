# Changelog

All notable changes to **ZeroLeak** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-11

### Added
- **Core Zero-Dependency Engine**:
  - Pure Python standard library implementation (`re`, `json`, `uuid`, `secrets`, `hashlib`, `threading`, `math`, `dataclasses`).
  - Pre-inference reversible tokenization: `mask(text, trace_id)` and `unmask(text, trace_id)`.
  - Recursive structured de-identification: `mask_object(obj, trace_id)` and `unmask_object(obj, trace_id)`.
- **Mathematical Checksums & Entropy Solvers**:
  - Standard Luhn algorithm (Mod-10) checksum for credit card validation (Visa, Mastercard, Amex, Discover).
  - Shannon entropy solver ($H \ge 3.2$) for generic secret token extraction.
  - Strict IPv4 octet bounds validation ($0 \le \text{octet} \le 255$, disallowing non-zero leading zeros).
- **Entity Detectors**:
  - `EMAIL`: RFC 5322 bounded-length ReDoS-immune regex.
  - `PHONE_US`: E.164, formatted, dotted, and standard 10-digit US phone formats.
  - `SSN`: Standard US SSN format with invalid area code rejection (000, 666, 900-999).
  - `CREDIT_CARD`: Multi-format card sequences validated with Luhn mod-10.
  - `IP_ADDRESS`: IPv4 and IPv6 addresses.
  - `API_KEY_HIGH_ENTROPY`: AWS, GitHub PATs, OpenAI keys, Stripe secret/restricted keys, Slack, Google API keys, Anthropic keys.
  - `BEARER_TOKEN`: HTTP authorization header tokens.
  - `JWT`: JSON Web Tokens (header.payload.signature).
  - `CRYPTO_WALLET`: Ethereum and Bitcoin addresses.
- **SessionVault**:
  - Ephemeral in-memory cryptographically salted token store.
  - Thread-safe RLock concurrency control.
  - Automatic TTL expiration and manual session purging.
  - Zero disk serialization guarantee (anti-leakage invariant).
- **Inter-Agent Prompt-Injection Firewall**:
  - Neutralizes indirect prompt injection attacks, zero-width characters, and markdown exfiltration payloads in untrusted tool outputs.
- **Configurable Sensitivity & Observation Mode**:
  - `mode="observe"` for staging observability and dry-run compliance audit logging.
  - `mode="enforce"` for active de-identification.
  - Configurable entity detector subsets and allowlists.
- **Developer Ergonomics**:
  - CLI runner with `--test`, `--list-entities`, `--print-config`, and `--firewall-test`.
  - Human-readable compliance audit receipt (`print_audit_receipt`).
- **Ecosystem Integration Bridges**:
  - `ZeroLeakHyperGateMiddleware`: transparent pre-flight masking and post-flight restitution for `HyperGateRouter`.
  - `protect_mcp_tool`: decorator wrapper for `ZeroMCP` tool handlers.
  - `ZeroLeakTraceTelemetry`: OpenTelemetry/AgentTrace non-leaking span attribute emitter.
- **CI & Release Tooling**:
  - `zeroleak-check`: zero-dependency verification and test suite grader.
  - `promote_to_standalone.py`: automated standalone repository scaffolding and git staging.
