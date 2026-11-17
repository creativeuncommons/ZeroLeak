"""
ZeroLeak <-> HyperGate Integration Bridge
=========================================
Middleware proxy connecting ZeroLeak de-identification engine to HyperGateRouter.

Ensures:
1. Inbound user messages are reversibly de-identified before System-1 routing,
   cost estimation, or external LLM API calls.
2. HyperGate and downstream models only observe masked synthetic tokens.
3. Post-inference completions are seamlessly restituted back to original plaintext.
4. Ephemeral session vault coordinates the lifecycle per trace_id.
"""

import os
import sys
import copy
import time
from typing import Dict, Any, Tuple, Optional, List

# Include local ZeroLeak package
ZEROMCP_PY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "zeroleak-py"))
if ZEROMCP_PY_DIR not in sys.path:
    sys.path.insert(0, ZEROMCP_PY_DIR)

from zeroleak import ZeroLeak, default_engine


class ZeroLeakHyperGateMiddleware:
    """
    Wraps a HyperGateRouter instance to provide pre-inference masking
    and post-inference restitution transparently.
    """
    def __init__(self, router: Any, zeroleak_engine: Optional[ZeroLeak] = None):
        self.router = router
        self.engine = zeroleak_engine or default_engine

    def handle_chat_completion(
        self, req_json: Dict[str, Any], headers: Optional[Dict[str, str]] = None
    ) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        """
        Intercepts chat completion request:
        1. Extracts or creates trace_id.
        2. Masks all message contents using ZeroLeak.
        3. Invokes the underlying HyperGateRouter.
        4. Restitutes any synthetic tokens in the returned LLM completion.
        """
        headers = headers or {}
        trace_id = (
            headers.get("x-hypergate-trace-id")
            or req_json.get("trace_id")
            or f"trc_zl_{os.urandom(6).hex()}"
        )

        # Clone request to prevent mutating caller's original references
        sanitized_req = copy.deepcopy(req_json)
        sanitized_req["trace_id"] = trace_id

        # 1. Pre-Inference Masking of Messages
        messages = sanitized_req.get("messages", [])
        for msg in messages:
            if "content" in msg and isinstance(msg["content"], str):
                msg["content"] = self.engine.mask(msg["content"], trace_id=trace_id)

        # 2. Invoke HyperGateRouter (calculates tokens and routes sanitized payload)
        status_code, resp_body, resp_headers = self.router.handle_chat_completion(
            sanitized_req, headers=headers
        )

        # 3. Post-Inference Restitution of Completion
        if status_code == 200 and isinstance(resp_body, dict):
            choices = resp_body.get("choices", [])
            for choice in choices:
                msg = choice.get("message", {})
                if "content" in msg and isinstance(msg["content"], str):
                    msg["content"] = self.engine.unmask(msg["content"], trace_id=trace_id)

        # 4. Attach ZeroLeak compliance header
        resp_headers = dict(resp_headers)
        receipt = self.engine.get_audit_receipt(trace_id)
        if receipt:
            resp_headers["x-zeroleak-masked-count"] = str(receipt.masked_count)
            resp_headers["x-zeroleak-mode"] = receipt.mode

        return status_code, resp_body, resp_headers
