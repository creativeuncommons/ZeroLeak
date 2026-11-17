"""
ZeroLeak <-> AgentTrace Integration Bridge
==========================================
Zero-dependency telemetry bridge recording ZeroLeak sanitization and restitution
events to AgentTrace spans without leaking raw PII or secrets into telemetry logs.

Adheres strictly to GenAI security telemetry conventions.
"""

import os
import sys
import json
from typing import Dict, Any, Optional

# Include local ZeroLeak package
ZEROMCP_PY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "zeroleak-py"))
if ZEROMCP_PY_DIR not in sys.path:
    sys.path.insert(0, ZEROMCP_PY_DIR)

from zeroleak import AuditReceipt, default_engine


class ZeroLeakTraceTelemetry:
    """
    Integrates with AgentTrace / OpenTelemetry tracers to attach
    non-leaking de-identification metrics to active spans.
    """
    @staticmethod
    def extract_span_attributes(receipt: AuditReceipt) -> Dict[str, Any]:
        """
        Converts an AuditReceipt into standardized OpenTelemetry span attributes.
        Strictly guarantees NO raw entity plaintext is present.
        """
        return {
            "pii.enabled": True,
            "pii.mode": receipt.mode,
            "pii.masked_count": receipt.masked_count,
            "pii.restituted_count": receipt.restituted_count,
            "pii.types_detected": json.dumps(receipt.types_detected),
            "pii.duration_ms": round(receipt.duration_ms, 3),
            "pii.zero_disk_leakage": receipt.zero_disk_leakage,
            "pii.storage_backend": "RAM_ONLY",
        }

    @staticmethod
    def record_to_span(span: Any, trace_id: str, engine=None):
        """
        Directly sets attributes on an active AgentTrace Span object.
        Compatible with AgentTrace Span.set_attribute().
        """
        active_engine = engine or default_engine
        receipt = active_engine.get_audit_receipt(trace_id)
        if not receipt:
            return

        attrs = ZeroLeakTraceTelemetry.extract_span_attributes(receipt)
        for k, v in attrs.items():
            if hasattr(span, "set_attribute"):
                span.set_attribute(k, v)
            elif hasattr(span, "attributes") and isinstance(span.attributes, dict):
                span.attributes[k] = v
