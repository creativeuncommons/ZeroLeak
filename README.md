# ZeroLeak (Project 4)
### Zero-Dependency Reversible PII & Secrets Sanitization Engine

<p align="center">
  <b>Ultra-Fast • Pure Standard Library • Reversible De-Identification • In-Memory Ephemeral Vault • ReDoS-Immune</b>
</p>

---

## 1. Mission Statement

**ZeroLeak** is an ultra-fast, zero-external-dependency, reversible de-identification and security sanitization proxy for autonomous AI agents and LLM gateways.

Pairs directly with **ZeroMCP**, **HyperGate**, and **AgentTrace** to eliminate the primary enterprise compliance blocker (**HIPAA, GDPR, SOC 2, PCI-DSS**) by guaranteeing that sensitive real-world entities never cross the network boundary to frontier model APIs:

* **Pre-Inference Reversible Tokenization**: Intercepts user prompts, tool arguments, and context, replacing sensitive PII (emails, phone numbers, SSNs, credit cards, IP addresses, crypto addresses) and security credentials (AWS keys, GitHub PATs, OpenAI keys, Stripe secrets, JWTs, Bearer tokens) with deterministic, type-aware synthetic tokens (e.g. `[EMAIL_1]`, `[API_KEY_1]`).
* **Ephemeral In-Memory Token Vault**: Manages an isolated, cryptographically salted session vault pairing synthetic tokens with original raw values with **zero disk leakage**.
* **Post-Inference Restitution**: Intercepts the LLM's response or downstream tool-call parameters, deterministically restoring the original sensitive values before presenting them to the user or executing on internal backends.
* **Inter-Agent Prompt-Injection Firewall**: Sanitizes untrusted tool outputs (e.g., web scrapes, untrusted DB rows) to neutralize indirect prompt injection payloads before they cross subagent boundaries.

---

## 2. Architecture & Ecosystem Workflow

```
┌────────────────────────────────────────────────────────┐
│               User / Client Application               │
└───────────────────────────┬────────────────────────────┘
                            │ (Raw Text with PII/Secrets)
                            ▼
┌────────────────────────────────────────────────────────┐
│           PROJECT 4: ZEROLEAK (Pre-Inference)          │
│ • Detects & Masks PII / Secrets -> [TOKEN_UUID]        │
│ • Stores Salted Mapping in Ephemeral Memory Vault      │
└───────────────────────────┬────────────────────────────┘
                            │ (Sanitized Text Only)
                            ▼
┌────────────────────────────────────────────────────────┐
│            HYPERGATE (System-1 & Routing)              │
│ • System-1 Routing (90% cheap / 10% reasoning)         │
│ • Observation / Cost Profiling Mode                    │
│ • Never sees raw PII                                   │
└───────────────┬────────────────────────┬───────────────┘
                │ (LLM Calls)            │ (Tool Invocations)
                ▼                        ▼
      [Cloud LLM APIs]         ┌────────────────────────┐
                               │  ZEROMCP (Tool Servers)│
                               │  • Tools executed via  │
                               │    safe ZeroLeak shim  │
                               └────────┬───────────────┘
                                        │
                                        ▼
┌────────────────────────────────────────────────────────┐
│          PROJECT 4: ZEROLEAK (Post-Inference)          │
│ • Restores [TOKEN_UUID] -> Original Values             │
│ • Emits Sanitized Spans to AGENTTRACE                  │
└────────────────────────────────────────────────────────┘
```

* **ZeroMCP Awareness**: Provides a zero-dependency middleware wrapper for ZeroMCP tool handlers (`@protect_mcp_tool`), ensuring tools receive restored parameters locally while external LLMs only see masked tokens.
* **HyperGate Awareness**: Plugs directly into `HyperGateRouter` as pre-flight / post-flight middleware (`ZeroLeakHyperGateMiddleware`). HyperGate calculates routing tiers and token costs on sanitized text.
* **AgentTrace Awareness**: Integrates with `AgentTracer` (`ZeroLeakTraceTelemetry`) to log de-identification telemetry (`pii.masked_count`, `pii.types_detected`, `pii.restituted_count`) without ever logging sensitive plaintext into `.jsonl` or SQLite spans.

---

## 3. Production Invariants

1. **Zero External Dependencies**: Pure Python standard library (`re`, `json`, `uuid`, `hashlib`, `secrets`, `math`, `threading`, `dataclasses`). Runs instantly out of the box with zero `pip install`.
2. **ReDoS Immunity & Checksum Validation**: Non-backtracking regex patterns, Luhn mod-10 algorithm for credit cards, Shannon entropy calculation ($H \ge 3.2$) for arbitrary high-entropy credentials.
3. **Configurable Sensitivity & Observation Mode**:
   - `mode="enforce"`: Actively tokenizes and restores.
   - `mode="observe"`: Non-destructive staging mode logging compliance advisories on what *would* be masked.
4. **Ephemeral Vault Safety**: Strict volatile memory per `trace_id` with automatic TTL cleanup (default: 30 minutes). Zero serialization to disk.

---

## 4. Quick-Test & Verification

```bash
# Developer Quick-Test
python3 zeroleak-py/zeroleak.py --test "Contact John at john@acme.com with key sk-live-982138402100000000000000"

# Run automated production grader & test suites
./scripts/zeroleak-check
```

See [USAGE.md](USAGE.md) for full developer integration guides and [SPECIFICATION.md](SPECIFICATION.md) for protocol details.

---

## 5. License

Apache 2.0. Open source and enterprise-ready.
