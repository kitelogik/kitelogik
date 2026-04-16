#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Kite Logik — Policy Gate Latency Benchmark

Measures OPA evaluation latency across three input types:
  simple_allow   — read_customer lookup, always allowed
  hitl_trigger   — approve_refund $350, triggers HITL
  hard_deny      — read_file /app/.env, hard-blocked by security.rego

Reports p50, p95, p99, and max for each type.
Answers the question: "Will governance slow down my agents?"

Prerequisites:
  docker compose up -d opa

Run with:
  .venv/bin/python benchmark.py
  .venv/bin/python benchmark.py --runs 2000 --concurrency 10
"""

import argparse
import asyncio
import os
import statistics
import time

from dotenv import load_dotenv

from kitelogik.anchor.credentials import CredentialBroker
from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.models import SessionContext, ToolCallInput
from kitelogik.tether.opa_client import OPAClient, OPAConnectionError

load_dotenv()


# ── ANSI ──────────────────────────────────────────────────────────────────────
B = "\033[1m"
D = "\033[2m"
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
RS = "\033[0m"
W = 70


def _pct(samples: list[float], p: int) -> float:
    return statistics.quantiles(samples, n=100)[p - 1] if len(samples) >= 100 else max(samples)


def _bar(char: str = "─") -> str:
    return char * W


async def bench_type(
    name: str,
    tool_name: str,
    args: dict,
    context: SessionContext,
    gate: PolicyGate,
    runs: int,
    concurrency: int,
) -> tuple[str, list[float]]:
    """Run `runs` evaluations with up to `concurrency` in-flight at once."""
    samples: list[float] = []
    sem = asyncio.Semaphore(concurrency)

    async def one() -> None:
        async with sem:
            call = ToolCallInput(action="call", tool_name=tool_name, args=args)
            t0 = time.perf_counter()
            await gate.evaluate_tool_call(call, context)
            samples.append((time.perf_counter() - t0) * 1000)

    tasks = [asyncio.create_task(one()) for _ in range(runs)]
    total = len(tasks)
    done = 0
    for coro in asyncio.as_completed(tasks):
        await coro
        done += 1
        if done % max(1, total // 10) == 0:
            pct = int(done / total * 100)
            print(f"  {D}{name:<20} {pct:>3}%{RS}", end="\r", flush=True)

    print(f"  {D}{name:<20} done  {RS}" + " " * 20)
    return name, samples


async def main(runs: int, concurrency: int, opa_url: str) -> None:
    opa = OPAClient(base_url=opa_url)
    broker = CredentialBroker()
    gate = PolicyGate(opa_client=opa, credential_broker=broker)

    try:
        await opa.health()
    except OPAConnectionError:
        print(f"\n{R}OPA is not running.{RS}  Start it with: docker compose up -d opa\n")
        return

    context = SessionContext(
        session_id="bench_001",
        user_role="support_agent",
        session_scopes=["read_customer", "approve_refund_under_100"],
        sandbox_verified=False,
    )

    scenarios: list[tuple[str, str, dict]] = [
        (
            "simple_allow",
            "list_transactions",
            {"customer_id": "cust_001"},
        ),
        (
            "hitl_trigger",
            "approve_refund",
            {"customer_id": "cust_001", "amount": 350.0},
        ),
        (
            "hard_deny",
            "read_file",
            {"path": "/app/.env"},
        ),
    ]

    print(f"\n{B}{'═' * W}{RS}")
    print(f"{B}  Kite Logik — Policy Gate Benchmark{RS}")
    print(f"  {D}OPA: {opa_url}  ·  runs={runs}  ·  concurrency={concurrency}{RS}")
    print(f"{B}{'═' * W}{RS}\n")

    results: list[tuple[str, list[float]]] = []
    for name, tool, args in scenarios:
        name, samples = await bench_type(name, tool, args, context, gate, runs, concurrency)
        results.append((name, samples))

    # ── Summary table ─────────────────────────────────────────────────────────
    col_name = 18
    col_num = 9

    print(
        f"\n{B}  {'Scenario':<{col_name}}  {'p50':>{col_num}}  {'p95':>{col_num}}  {'p99':>{col_num}}  {'max':>{col_num}}{RS}"  # noqa: E501
    )
    print(f"  {D}{_bar('─')}{RS}")

    for name, samples in results:
        p50 = statistics.median(samples)
        p95 = _pct(samples, 95)
        p99 = _pct(samples, 99)
        mx = max(samples)

        def fmt(ms: float) -> str:
            color = G if ms < 10 else Y if ms < 30 else R
            return f"{color}{ms:>{col_num - 2}.1f}ms{RS}"

        print(f"  {name:<{col_name}}  {fmt(p50)}  {fmt(p95)}  {fmt(p99)}  {fmt(mx)}")

    all_samples = [s for _, ss in results for s in ss]
    p50 = statistics.median(all_samples)
    p95 = _pct(all_samples, 95)
    p99 = _pct(all_samples, 99)
    mx = max(all_samples)

    def fmt(ms: float) -> str:
        color = G if ms < 10 else Y if ms < 30 else R
        return f"{color}{ms:>{col_num - 2}.1f}ms{RS}"

    print(f"  {D}{_bar('─')}{RS}")
    print(f"  {'overall':<{col_name}}  {fmt(p50)}  {fmt(p95)}  {fmt(p99)}  {fmt(mx)}")
    print(f"\n  {D}total evaluations: {len(all_samples):,}  ·  OPA URL: {opa_url}{RS}")
    print(f"{B}{'═' * W}{RS}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kite Logik policy gate latency benchmark")
    parser.add_argument(
        "--runs", type=int, default=1000, help="Number of evaluations per scenario (default: 1000)"
    )
    parser.add_argument(
        "--concurrency", type=int, default=5, help="Maximum concurrent OPA requests (default: 5)"
    )
    parser.add_argument(
        "--opa",
        metavar="URL",
        default=os.getenv("OPA_BASE_URL", "http://localhost:8181"),
        help="OPA base URL (default: http://localhost:8181)",
    )
    args = parser.parse_args()
    asyncio.run(main(args.runs, args.concurrency, args.opa))
