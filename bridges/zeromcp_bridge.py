"""
ZeroLeak <-> ZeroMCP Integration Bridge
=======================================
Zero-dependency middleware wrapper for ZeroMCP tool handlers.

Guarantees:
1. When external LLMs invoke tools using synthetic tokens (e.g. [EMAIL_1]),
   the tool receives original restored parameters locally.
2. Tool execution results are passed through the ZeroLeak prompt-injection
   firewall to neutralize indirect injection payloads from untrusted data sources.
3. Outbound tool results are re-masked if new sensitive entities are generated.
"""

import os
import sys
import functools
from typing import Dict, Any, Callable, Optional

# Include local ZeroLeak package
ZEROMCP_PY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "zeroleak-py"))
if ZEROMCP_PY_DIR not in sys.path:
    sys.path.insert(0, ZEROMCP_PY_DIR)

from zeroleak import ZeroLeak, default_engine


def protect_mcp_tool(
    handler: Optional[Callable[..., Any]] = None,
    *,
    engine: Optional[ZeroLeak] = None,
    trace_id_param: str = "_trace_id",
    sanitize_prompt_injection: bool = True,
    remask_output: bool = True
):
    """
    Decorator for ZeroMCP tool definitions.
    
    Usage:
        @protect_mcp_tool
        def send_email(to: str, subject: str, body: str):
            # 'to' arrives as 'alice@acme.com', even if LLM provided '[EMAIL_1]'
            ...
    """
    actual_engine = engine or default_engine

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            trace_id = kwargs.pop(trace_id_param, None) or os.getenv("ZEROLEAK_CURRENT_TRACE_ID", "default_trace")

            # 1. Unmask all incoming arguments
            unmasked_args = [actual_engine.unmask_object(arg, trace_id) for arg in args]
            unmasked_kwargs = {k: actual_engine.unmask_object(v, trace_id) for k, v in kwargs.items()}

            # 2. Execute local tool
            raw_result = fn(*unmasked_args, **unmasked_kwargs)

            # 3. Optional prompt injection firewall defense
            if sanitize_prompt_injection and isinstance(raw_result, str):
                raw_result = actual_engine.sanitize_tool_output(raw_result)

            # 4. Optional re-masking of tool outputs so sensitive DB rows/content stay tokenized
            if remask_output and isinstance(raw_result, str):
                raw_result = actual_engine.mask(raw_result, trace_id=trace_id)
            elif remask_output and isinstance(raw_result, (dict, list)):
                raw_result = actual_engine.mask_object(raw_result, trace_id=trace_id)

            return raw_result
        return wrapper

    if handler is not None:
        return decorator(handler)
    return decorator
