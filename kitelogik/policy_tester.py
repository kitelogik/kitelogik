# SPDX-License-Identifier: Apache-2.0
"""
Kite Logik Policy Tester

Evaluate any OPA/Rego policy file against a JSON input without running a
full agent session. Useful for iterating on policy rules before deploying.

Usage:
    python -m kitelogik.policy_tester \\
        --policy policies/examples/example_financial_thresholds.rego \\
        --input '{"action":"approve_refund","args":{"amount":250},
                  "context":{"user_role":"support_agent","session_scopes":["approve_refund_under_100"]}}'

    # Or point --input at a JSON file:
    python -m kitelogik.policy_tester \\
        --policy policies/financial.rego \\
        --input test_input.json

OPA must be running:
    docker compose up -d opa

The tester uploads the policy to OPA temporarily, evaluates the input, and
then removes the test policy. It does not affect the live policy bundle.
"""

import argparse
import asyncio
import json
import os
import sys
import uuid

import httpx

# ── ANSI ──────────────────────────────────────────────────────────────────────
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
B = "\033[1m"
D = "\033[2m"
RS = "\033[0m"


def _parse_package(rego_text: str) -> str:
    """Extract the package path from a Rego file, e.g. 'kitelogik.financial'."""
    for line in rego_text.splitlines():
        line = line.strip()
        if line.startswith("package "):
            return line.removeprefix("package ").strip()
    raise ValueError("Could not find 'package' declaration in Rego file")


def _package_to_url_path(package: str) -> str:
    """Convert 'kitelogik.financial' → 'kitelogik/financial'."""
    return package.replace(".", "/")


async def run(policy_path: str, input_data: dict, opa_url: str) -> None:
    policy_id = f"kitelogik_test_{uuid.uuid4().hex[:8]}"
    opa_url = opa_url.rstrip("/")

    # Read the policy
    try:
        with open(policy_path) as f:
            rego_text = f.read()
    except FileNotFoundError:
        print(f"{R}Error:{RS} policy file not found: {policy_path}")
        sys.exit(2)

    try:
        package = _parse_package(rego_text)
    except ValueError as e:
        print(f"{R}Error:{RS} {e}")
        sys.exit(2)

    data_path = _package_to_url_path(package)

    print(f"\n{B}Policy Tester{RS}")
    print(f"  policy   {D}{policy_path}{RS}")
    print(f"  package  {D}{package}{RS}")
    print(f"  opa      {D}{opa_url}{RS}")

    async with httpx.AsyncClient(timeout=5.0) as client:
        # ── Upload policy to OPA ────────────────────────────────────────────
        try:
            r = await client.put(
                f"{opa_url}/v1/policies/{policy_id}",
                content=rego_text.encode(),
                headers={"Content-Type": "text/plain"},
            )
        except httpx.ConnectError:
            print(f"\n{R}OPA is not running.{RS}  Start it with: docker compose up -d opa\n")
            sys.exit(2)

        if r.status_code != 200:
            print(f"\n{R}Failed to load policy into OPA:{RS}")
            print(f"  HTTP {r.status_code}: {r.text}\n")
            sys.exit(2)

        # ── Evaluate ────────────────────────────────────────────────────────
        try:
            r = await client.post(
                f"{opa_url}/v1/data/{data_path}",
                json={"input": input_data},
            )
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            print(f"\n{R}OPA evaluation error:{RS} HTTP {e.response.status_code}")
            print(f"  {e.response.text}\n")
            await client.delete(f"{opa_url}/v1/policies/{policy_id}")
            sys.exit(2)

        result = r.json().get("result", {})

        # ── Cleanup ─────────────────────────────────────────────────────────
        await client.delete(f"{opa_url}/v1/policies/{policy_id}")

    # ── Print result ─────────────────────────────────────────────────────────
    print(f"\n{B}Input:{RS}")
    print(f"  {D}{json.dumps(input_data, indent=2).replace(chr(10), chr(10) + '  ')}{RS}")

    print(f"\n{B}Result:{RS}")
    if not result:
        print(f"  {Y}(empty — package evaluated but produced no output){RS}")
    else:
        for key, value in result.items():
            if key == "allow":
                label = f"{G}{B}ALLOW{RS}" if value else f"{R}{B}DENY{RS}"
                print(f"  allow        {label}")
            elif key == "deny":
                label = f"{R}{B}HARD BLOCK{RS}" if value else f"{G}no hard block{RS}"
                print(f"  deny         {label}")
            elif key == "requires_hitl":
                label = f"{Y}{B}HITL REQUIRED{RS}" if value else f"{G}auto{RS}"
                print(f"  requires_hitl  {label}")
            elif key == "risk_tier":
                print(f"  risk_tier    {D}{value}{RS}")
            else:
                print(f"  {key:<14}{D}{json.dumps(value)}{RS}")

    print()

    # ── Exit code ─────────────────────────────────────────────────────────────
    # 0 = allow   (decision is explicitly allow=true)
    # 1 = deny    (allow=false, or hard deny, or requires_hitl)
    # 2 = error   (OPA unreachable, parse failure, input validation — raised earlier)
    # Scriptable: CI policy-change checks can rely on these codes.
    if result.get("allow") is True and not result.get("deny") and not result.get("requires_hitl"):
        return 0
    return 1


def _load_input(raw: str) -> dict:
    """Accept a JSON string or a path to a JSON file."""
    raw = raw.strip()
    # Try as a file path first
    if os.path.isfile(raw):
        with open(raw) as f:
            return json.load(f)
    # Otherwise parse as an inline JSON string
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"{R}Error:{RS} --input is neither a valid JSON string nor an existing file.")
        print(f"  {e}")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate a Rego policy against a JSON input via OPA.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--policy",
        "-p",
        required=True,
        metavar="PATH",
        help="Path to the .rego policy file",
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        metavar="JSON_OR_FILE",
        help="JSON input string or path to a JSON file",
    )
    parser.add_argument(
        "--opa",
        default=os.getenv("OPA_BASE_URL", "http://localhost:8181"),
        metavar="URL",
        help="OPA base URL (default: http://localhost:8181 or OPA_BASE_URL env var)",
    )

    args = parser.parse_args()
    input_data = _load_input(args.input)
    exit_code = asyncio.run(run(args.policy, input_data, args.opa))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
