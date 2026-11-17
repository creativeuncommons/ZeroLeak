#!/usr/bin/env python3
"""
ZeroLeak Micro-Benchmark Suite
==============================
Reproducible performance, latency, memory (RSS), and throughput benchmarks
measuring zero-latency PII de-identification, deterministic tokenization,
and session vault roundtrips.

Zero external dependencies (pure Python standard library).
"""

import os
import sys
import time
import uuid
import statistics
import resource
from typing import Dict, Any, List

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BENCHMARK_DIR)
PY_DIR = os.path.join(PROJECT_ROOT, "zeroleak-py")

if PY_DIR not in sys.path:
    sys.path.insert(0, PY_DIR)

from zeroleak import ZeroLeak, SessionVault, luhn_checksum


def get_current_rss_kb() -> int:
    """Returns current process Resident Set Size (RSS) in KB."""
    usage = resource.getrusage(resource.RUSAGE_SELF)
    if sys.platform == "darwin":
        return int(usage.ru_maxrss / 1024)
    return int(usage.ru_maxrss)


def run_benchmarks(iterations: int = 2000):
    print("============================================================")
    print(f"🛡️  ZeroLeak Micro-Benchmark Suite ({iterations:,} iterations)")
    print("============================================================\n")

    initial_rss = get_current_rss_kb()
    print(f"📊 Baseline Process Memory (RSS): {initial_rss:,} KB (~{initial_rss/1024:.2f} MB)")

    # Sample payloads with realistic valid PII:
    # Valid SSN: 123-45-6789
    # Valid Luhn Visa: 4532-0151-1283-0366
    # Valid high-entropy token: ghp_1234567890abcdef1234567890ABCDEF12
    # Non-allowlisted email: user.alpha@enterprise-defense.org
    small_payload = (
        "User user.alpha@enterprise-defense.org from 192.168.1.100 "
        "submitted SSN 123-45-6789 and API token ghp_1234567890abcdef1234567890ABCDEF12."
    )
    medium_payload = (
        "Customer Account Record: "
        "Contact: sarah.connor@cyberdyne-systems.com, Phone: +1-555-867-5309. "
        "Tax ID: 456-78-1234. Card: 4532-0151-1283-0366. "
        "Bearer auth: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_p_m1xV_y_example. "
        "Query: Validate billing transaction for invoice #98124.\n"
    ) * 3  # ~1.2 KB

    large_payload = medium_payload * 10  # ~12 KB

    engine = ZeroLeak(mode="enforce")
    bench_trace_id = f"bench_{uuid.uuid4().hex[:8]}"

    # 1. Benchmark: Small Prompt Redaction Latency
    small_latencies_us: List[float] = []
    for i in range(iterations):
        t0 = time.perf_counter()
        engine.mask(small_payload, trace_id=f"{bench_trace_id}_{i}")
        t1 = time.perf_counter()
        small_latencies_us.append((t1 - t0) * 1_000_000)

    # 2. Benchmark: Medium Prompt Redaction Latency (~1.2 KB)
    medium_latencies_us: List[float] = []
    for i in range(iterations):
        t0 = time.perf_counter()
        engine.mask(medium_payload, trace_id=f"{bench_trace_id}_med_{i}")
        t1 = time.perf_counter()
        medium_latencies_us.append((t1 - t0) * 1_000_000)

    # 3. Benchmark: Large Prompt Redaction Latency (~12 KB)
    large_latencies_us: List[float] = []
    for i in range(iterations // 4):
        t0 = time.perf_counter()
        engine.mask(large_payload, trace_id=f"{bench_trace_id}_large_{i}")
        t1 = time.perf_counter()
        large_latencies_us.append((t1 - t0) * 1_000_000)

    # 4. Benchmark: Session Vault Roundtrip (Mask -> Unmask)
    roundtrip_latencies_us: List[float] = []
    for i in range(iterations):
        tid = f"{bench_trace_id}_rt_{i}"
        t0 = time.perf_counter()
        masked = engine.mask(small_payload, trace_id=tid)
        unmasked = engine.unmask(masked, trace_id=tid)
        t1 = time.perf_counter()
        roundtrip_latencies_us.append((t1 - t0) * 1_000_000)

    small_p50 = statistics.median(small_latencies_us)
    small_p90 = sorted(small_latencies_us)[int(len(small_latencies_us) * 0.90)]
    small_p99 = sorted(small_latencies_us)[int(len(small_latencies_us) * 0.99)]
    small_ops = 1_000_000 / small_p50 if small_p50 > 0 else 0

    med_p50 = statistics.median(medium_latencies_us)
    med_p90 = sorted(medium_latencies_us)[int(len(medium_latencies_us) * 0.90)]
    med_p99 = sorted(medium_latencies_us)[int(len(medium_latencies_us) * 0.99)]
    med_throughput_mb_s = (len(medium_payload) * 1_000_000 / med_p50) / (1024 * 1024)

    rt_p50 = statistics.median(roundtrip_latencies_us)
    rt_p90 = sorted(roundtrip_latencies_us)[int(len(roundtrip_latencies_us) * 0.90)]
    rt_p99 = sorted(roundtrip_latencies_us)[int(len(roundtrip_latencies_us) * 0.99)]

    final_rss = get_current_rss_kb()

    print("------------------------------------------------------------")
    print("📈 Benchmark Results Summary")
    print("------------------------------------------------------------")
    print("Component: Small Prompt Redaction (160 B, SSN + Email + Key + IP)")
    print(f"  p50: {small_p50:.2f} µs | p90: {small_p90:.2f} µs | p99: {small_p99:.2f} µs")
    print(f"  Throughput: {small_ops:,.0f} payloads/sec (< 0.5 ms budget: {'✅ MET' if small_p99 < 500 else '❌ EXCEEDED'})")
    print()
    print("Component: Medium Prompt Redaction (~1.2 KB, Multiple PII & Secrets)")
    print(f"  p50: {med_p50:.2f} µs | p90: {med_p90:.2f} µs | p99: {med_p99:.2f} µs")
    print(f"  Throughput: {med_throughput_mb_s:.2f} MB/sec")
    print()
    print("Component: Session Vault Roundtrip (Mask + Unmask Full Restitution)")
    print(f"  p50: {rt_p50:.2f} µs | p90: {rt_p90:.2f} µs | p99: {rt_p99:.2f} µs")
    print(f"  Throughput: {1_000_000 / rt_p50:,.0f} roundtrips/sec")
    print()
    print(f"🧠 Final Process Memory (RSS): {final_rss:,} KB (Delta: +{final_rss - initial_rss:,} KB)")
    print("============================================================\n")

    print("📋 Markdown Summary Table:")
    print("| Metric | Small (160 B) | Medium (1.2 KB) | Vault Roundtrip |")
    print("| :--- | :---: | :---: | :---: |")
    print(f"| **p50 Latency** | **{small_p50:.2f} µs** | **{med_p50:.2f} µs** | **{rt_p50:.2f} µs** |")
    print(f"| **p90 Latency** | **{small_p90:.2f} µs** | **{med_p90:.2f} µs** | **{rt_p90:.2f} µs** |")
    print(f"| **p99 Latency** | **{small_p99:.2f} µs** | **{med_p99:.2f} µs** | **{rt_p99:.2f} µs** |")
    print(f"| **Throughput** | **{small_ops:,.0f} req/s** | **{med_throughput_mb_s:.2f} MB/s** | **{1_000_000 / rt_p50:,.0f} ops/s** |")


if __name__ == "__main__":
    run_benchmarks()
