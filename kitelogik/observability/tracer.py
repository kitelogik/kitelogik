# SPDX-License-Identifier: Apache-2.0
import sys

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

_provider: TracerProvider | None = None
_trace_fh = None  # file handle for trace_file mode; closed on re-init

# Always-on in-memory exporter — powers the dashboard Traces panel.
# Holds the last 500 finished spans in process; no external service required.
_mem_exporter = InMemorySpanExporter()
_MEM_CAP = 500  # spans retained


def setup_tracer(
    service_name: str = "kitelogik",
    testing: bool = False,
    trace_file: str | None = None,
    otlp_endpoint: str | None = None,
) -> None:
    """
    Configure the global OpenTelemetry tracer.

    Parameters
    ----------
    service_name : str
            Identifies this service in traces.
    testing : bool
            When True, skips all file/network export (no I/O, safe for pytest).
    trace_file : str or None
            Path to write JSON span output. Ignored when ``otlp_endpoint`` is set.
    otlp_endpoint : str or None
            OTLP HTTP endpoint (e.g. ``"http://localhost:4318"``) for enterprise
            observability stacks (Tempo/Grafana). Optional — the dashboard
            Traces panel works without it via the in-memory exporter.
    """
    global _provider, _trace_fh
    # Close previous trace file handle if re-initialising
    if _trace_fh is not None:
        _trace_fh.close()
        _trace_fh = None
    # Clear accumulated spans from previous setup (e.g. across test runs)
    _mem_exporter.clear()
    resource = Resource.create({"service.name": service_name})
    _provider = TracerProvider(resource=resource)

    # Always capture spans in-process for the dashboard traces panel.
    _provider.add_span_processor(SimpleSpanProcessor(_mem_exporter))

    if testing:
        pass  # in-memory only — no file/network I/O
    elif otlp_endpoint:
        # Enterprise: also forward to external collector (Tempo/Jaeger/etc.)
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        exporter = OTLPSpanExporter(endpoint=f"{otlp_endpoint.rstrip('/')}/v1/traces")
        _provider.add_span_processor(BatchSpanProcessor(exporter))
    elif trace_file:
        _trace_fh = open(trace_file, "a")  # noqa: SIM115
        _provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter(out=_trace_fh)))
    else:
        # Write to stderr so demo stdout stays clean
        _provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter(out=sys.stderr)))

    trace.set_tracer_provider(_provider)


def get_tracer(name: str = "kitelogik") -> trace.Tracer:
    if _provider is None:
        setup_tracer()
    return trace.get_tracer(name)


def get_finished_spans() -> list[dict]:
    """
    Return finished spans as JSON-serialisable dicts for the dashboard Traces panel.

    Spans are grouped and rendered as per-agent-session waterfalls in the UI.
    Returns the most recent _MEM_CAP spans; older spans are silently dropped.
    """
    raw = _mem_exporter.get_finished_spans()
    result = []
    for span in raw[-_MEM_CAP:]:
        ctx = span.get_span_context()
        attrs = dict(span.attributes or {})
        result.append(
            {
                "trace_id": format(ctx.trace_id, "032x"),
                "span_id": format(ctx.span_id, "016x"),
                "parent_span_id": format(span.parent.span_id, "016x") if span.parent else None,
                "name": span.name,
                "start_ms": span.start_time // 1_000_000,
                "end_ms": span.end_time // 1_000_000,
                "duration_ms": (span.end_time - span.start_time) // 1_000_000,
                "status": span.status.status_code.name,
                # Kite Logik semantic attributes
                "session_id": attrs.get("kitelogik.session_id", ""),
                "user_role": attrs.get("kitelogik.user_role", ""),
                "tool_name": attrs.get("kitelogik.tool_name", ""),
                "policy_allow": attrs.get("kitelogik.policy.allow"),
                "policy_deny": attrs.get("kitelogik.policy.deny"),
                "policy_hitl": attrs.get("kitelogik.policy.requires_hitl"),
                "risk_tier": attrs.get("kitelogik.policy.risk_tier", ""),
                "reason": attrs.get("kitelogik.policy.reason", ""),
                "duration_ms_detail": {
                    "schema_validate": None,
                    "opa_evaluate": None,
                },
            }
        )
    return result
