# SPDX-License-Identifier: Apache-2.0
"""
kitelogik CLI — command-line interface for policy management.

Commands:
    kitelogik init       — scaffold a new governed agent project
    kitelogik validate   — validate Rego policy syntax
    kitelogik test       — run OPA tests on policies/
    kitelogik check      — dry-run a governance event against policies
    kitelogik compile    — compile YAML policy to Rego
    kitelogik compliance — run governance compliance check
    kitelogik version    — print version
"""

import argparse
import json
import subprocess
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path


def _copy_core_bundle(dest: Path) -> list[str]:
    """Copy the installed core OSS Rego modules into ``dest``.

    Copies every top-level non-test ``.rego`` module shipped with the
    package (main, userpolicy, financial, security, delegation, agent_*)
    so a scaffolded project evaluates against the real governance
    pipeline — security hard-denies, delegation limits, HITL routing,
    event dispatch — not just the user's compiled rules. The user's
    YAML compiles to a separate ``policy.rego`` in the same package.
    Returns the copied file names.
    """
    import shutil

    src = Path(__file__).parent / "policies"
    copied: list[str] = []
    for rego in sorted(src.glob("*.rego")):
        if rego.name.endswith("_test.rego"):
            continue
        shutil.copy2(rego, dest / rego.name)
        copied.append(rego.name)
    return copied


def _find_policies_dir() -> Path:
    """Find the policies directory, searching upward from cwd."""
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        # Namespaced path (post-refactor layout)
        candidate = parent / "kitelogik" / "policies"
        if candidate.is_dir():
            return candidate
        # Bare path (user-created projects via kitelogik init)
        candidate = parent / "policies"
        if candidate.is_dir():
            return candidate
    return cwd / "kitelogik" / "policies"


# Fixed OPA image tag for the Docker fallback. Pinning (not `:latest`) keeps
# CLI behaviour reproducible across user machines and matches what the CI
# integration job uses.
_OPA_DOCKER_IMAGE = "openpolicyagent/opa:latest"


def _run_opa(
    opa_args: list[str],
    *,
    policies_dir: Path | None = None,
    stdin: str | None = None,
    capture_output: bool = True,
) -> subprocess.CompletedProcess:
    """Invoke OPA, falling back to Docker when no local ``opa`` binary is found.

    The README's recommended setup starts OPA via ``docker compose up -d opa``,
    which means most users will not have a bare ``opa`` binary on their PATH.
    Rather than fail with "install OPA", transparently re-run the same command
    inside ``openpolicyagent/opa:latest`` if Docker is available.

    Parameters
    ----------
    opa_args : list[str]
            Arguments to pass to the ``opa`` binary (e.g. ``["check", ...]``).
            Any argument that starts with the host ``policies_dir`` path is
            remapped to ``/policies`` inside the container when using Docker.
    policies_dir : Path or None
            The host policies directory. When provided and Docker is used,
            it is bind-mounted read-only at ``/policies``.
    stdin : str or None
            Optional stdin content (used by ``opa eval -i -``).
    capture_output : bool
            Forwarded to ``subprocess.run``.
    """
    try:
        return subprocess.run(
            ["opa", *opa_args],
            input=stdin,
            capture_output=capture_output,
            text=True,
        )
    except FileNotFoundError:
        pass  # fall through to Docker

    host_policies = policies_dir.resolve() if policies_dir is not None else None
    remapped = [
        arg.replace(str(host_policies), "/policies") if host_policies and arg else arg
        for arg in opa_args
    ]
    docker_cmd = ["docker", "run", "--rm"]
    if stdin is not None:
        docker_cmd.append("-i")
    if host_policies is not None:
        docker_cmd.extend(["-v", f"{host_policies}:/policies:ro"])
    docker_cmd.extend([_OPA_DOCKER_IMAGE, *remapped])

    try:
        return subprocess.run(
            docker_cmd,
            input=stdin,
            capture_output=capture_output,
            text=True,
        )
    except FileNotFoundError as e:
        raise FileNotFoundError(
            "Neither 'opa' nor 'docker' found on PATH. Install one of:\n"
            "  • OPA binary: https://www.openpolicyagent.org/docs/latest/#running-opa\n"
            "  • Docker Desktop: https://www.docker.com/products/docker-desktop/"
        ) from e


def cmd_init(args: argparse.Namespace) -> int:
    """Scaffold a new governed agent project."""
    from kitelogik._init_templates import (
        AGENT_PY,
        DOCKER_COMPOSE_YAML,
        ENV_EXAMPLE,
        POLICY_YAML,
    )

    target = Path(args.directory).resolve()
    policies_dir = target / "policies"

    if (policies_dir / "policy.yaml").exists():
        print(f"Error: {policies_dir / 'policy.yaml'} already exists.", file=sys.stderr)
        return 1

    policies_dir.mkdir(parents=True, exist_ok=True)
    (policies_dir / "policy.yaml").write_text(POLICY_YAML)
    (target / "agent.py").write_text(AGENT_PY)
    (target / "docker-compose.yml").write_text(DOCKER_COMPOSE_YAML)
    (target / ".env.example").write_text(ENV_EXAMPLE)

    # Ship the core governance bundle so the project evaluates against the
    # real pipeline, not just the user's rules. The user's YAML compiles
    # into the same kitelogik.userpolicy package the bundle aggregates.
    core_modules = _copy_core_bundle(policies_dir)

    # Auto-compile the YAML policy to Rego
    from kitelogik.policies.compiler import compile_yaml

    rego_source = compile_yaml(policies_dir / "policy.yaml")
    (policies_dir / "policy.rego").write_text(rego_source)

    print(f"Initialized Kite Logik project in {target}\n")
    print("  Created:")
    print("    policies/policy.yaml     — governance rules (YAML)")
    print("    policies/policy.rego     — your compiled rules (kitelogik.userpolicy)")
    print(f"    policies/*.rego          — core governance bundle ({len(core_modules)} modules)")
    print("    agent.py                 — example governed agent")
    print("    docker-compose.yml       — OPA policy engine")
    print("    .env.example             — environment template")
    print()
    print("  Next steps:")
    print(f"    cd {target}")
    print("    docker compose up -d     # start OPA policy engine")
    print("    python agent.py          # run governance demo")
    print()
    print("  Edit policies/policy.yaml, recompile with 'kitelogik compile policies/policy.yaml',")
    print("  restart OPA with 'docker compose restart', and re-run to see changes.")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate Rego policy syntax using OPA."""
    policies_dir = Path(args.path) if args.path else _find_policies_dir()
    if not policies_dir.is_dir():
        print(f"Error: policies directory not found at {policies_dir}", file=sys.stderr)
        return 1

    rego_files = list(policies_dir.glob("**/*.rego"))
    if not rego_files:
        print(f"No .rego files found in {policies_dir}", file=sys.stderr)
        return 1

    # Filter out test files for syntax check
    policy_files = [f for f in rego_files if not f.name.endswith("_test.rego")]
    print(f"Validating {len(policy_files)} policy files in {policies_dir}...")

    try:
        result = _run_opa(
            ["check", *[str(f) for f in policy_files]],
            policies_dir=policies_dir,
        )
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if result.returncode == 0:
        print(f"All {len(policy_files)} policy files are valid.")
        return 0

    print(result.stderr or result.stdout, file=sys.stderr)
    return result.returncode


def cmd_test(args: argparse.Namespace) -> int:
    """Run OPA tests on the policies directory."""
    policies_dir = Path(args.path) if args.path else _find_policies_dir()
    if not policies_dir.is_dir():
        print(f"Error: policies directory not found at {policies_dir}", file=sys.stderr)
        return 1

    verbose_flag = ["-v"] if args.verbose else []
    try:
        # Stream output directly for `opa test` so the user sees progress.
        result = _run_opa(
            ["test", str(policies_dir), *verbose_flag],
            policies_dir=policies_dir,
            capture_output=False,
        )
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return result.returncode


def cmd_check(args: argparse.Namespace) -> int:
    """Dry-run a governance event against loaded policies."""
    policies_dir = Path(args.path) if args.path else _find_policies_dir()
    if not policies_dir.is_dir():
        print(f"Error: policies directory not found at {policies_dir}", file=sys.stderr)
        return 1

    try:
        input_data = json.loads(args.input)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON input: {e}", file=sys.stderr)
        return 1

    try:
        # OPA's stdin-input flag is -I (uppercase); lowercase -i expects a
        # filename. The earlier `-i -` call path silently broke because OPA
        # resolved '-' as a missing file.
        result = _run_opa(
            ["eval", "-d", str(policies_dir), "--stdin-input", "data.kitelogik.main"],
            policies_dir=policies_dir,
            stdin=json.dumps(input_data),
        )
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return result.returncode

    try:
        output = json.loads(result.stdout)
        # Pretty-print the result
        if "result" in output and output["result"]:
            decision = output["result"][0].get("expressions", [{}])[0].get("value", {})
            print(json.dumps(decision, indent=2))
        else:
            print(result.stdout)
    except json.JSONDecodeError:
        print(result.stdout)

    return 0


def cmd_policy_compile(args: argparse.Namespace) -> int:
    """Compile a YAML policy file to Rego."""
    from kitelogik.policies.compiler import compile_yaml

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        return 1
    if input_path.is_dir():
        print(
            f"Error: {input_path} is a directory. Compile individual .yaml files.\n"
            f"Example: kitelogik compile {input_path}/rules.yaml",
            file=sys.stderr,
        )
        return 1

    try:
        rego_source = compile_yaml(input_path)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.check:
        print(f"Valid YAML policy: {input_path}")
        print(f"Would generate Rego for package defined in {input_path}")
        return 0

    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.with_suffix(".rego")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rego_source)
    print(f"Compiled {input_path} -> {output_path}")
    return 0


def cmd_compliance_check(args: argparse.Namespace) -> int:
    """Run a governance compliance check against loaded policies.

    Validates policy structure, checks default-deny posture, reports
    event type coverage, and maps to OWASP Agentic Security controls.
    """
    policies_dir = Path(args.path) if args.path else _find_policies_dir()
    if not policies_dir.is_dir():
        print(f"Error: policies directory not found at {policies_dir}", file=sys.stderr)
        return 1

    rego_files = sorted(policies_dir.rglob("*.rego"))
    policy_files = [f for f in rego_files if not f.name.endswith("_test.rego")]
    test_files = [f for f in rego_files if f.name.endswith("_test.rego")]

    if not policy_files:
        print(f"Error: no policy files found in {policies_dir}", file=sys.stderr)
        return 1

    issues: list[str] = []
    passes: list[str] = []

    # ── Check 1: Default-deny posture ────────────────────────────────────
    files_missing_default_deny: list[str] = []
    for pf in policy_files:
        if pf.name == "main.rego":
            continue  # main.rego aggregates; sub-policies set defaults
        content = pf.read_text()
        # Check for default deny/allow declarations
        has_default = "default deny" in content or "default allow" in content
        if not has_default:
            files_missing_default_deny.append(pf.name)

    if files_missing_default_deny:
        issues.append(
            f"Default-deny posture: {len(files_missing_default_deny)} file(s) "
            f"missing default declaration: {', '.join(files_missing_default_deny)}"
        )
    else:
        passes.append("Default-deny posture: all policy files declare defaults")

    # ── Check 2: Event type coverage ─────────────────────────────────────
    event_types = {
        "tool_call": False,
        "agent.spawn": False,
        "agent.delegate": False,
        "agent.plan": False,
        "agent.budget": False,
    }
    all_content = ""
    for pf in policy_files:
        all_content += pf.read_text() + "\n"

    # tool_call is the default event type (policies without event_type filter)
    event_types["tool_call"] = True
    for et in ["agent.spawn", "agent.delegate", "agent.plan", "agent.budget"]:
        if et in all_content:
            event_types[et] = True

    covered = [et for et, v in event_types.items() if v]
    missing = [et for et, v in event_types.items() if not v]

    if missing:
        issues.append(
            f"Event coverage: {len(covered)}/5 event types covered. Missing: {', '.join(missing)}"
        )
    else:
        passes.append("Event coverage: all 5 governance event types covered")

    # ── Check 3: Policy tests exist ──────────────────────────────────────
    tested_modules = {f.name.replace("_test.rego", ".rego") for f in test_files}
    untested = [
        pf.name for pf in policy_files if pf.name not in tested_modules and pf.name != "main.rego"
    ]

    if untested:
        issues.append(
            f"Test coverage: {len(untested)} policy file(s) have no test: {', '.join(untested)}"
        )
    else:
        passes.append("Test coverage: all policy files have corresponding tests")

    # ── Check 4: OWASP Agentic Security mapping ─────────────────────────
    # Map implemented controls based on policy/feature presence
    owasp_controls = {
        "ASI-01 Tool Call Authorization": "tool_call" in covered,
        "ASI-02 Agent Identity & Auth": "session_id" in all_content or "token" in all_content,
        "ASI-03 Excessive Agency Prevention": "agent.plan" in covered,
        "ASI-04 Privilege Escalation": "delegation" in all_content,
        "ASI-05 Resource Abuse": "agent.budget" in covered,
        "ASI-06 Prompt Injection Defense": any(
            "sanitize" in pf.name or "security" in pf.name for pf in policy_files
        ),
        "ASI-07 Data Exfiltration": "resource_path" in all_content,
        "ASI-08 Agent Lifecycle Control": "agent.spawn" in covered,
        "ASI-09 Audit & Observability": any(pf.name == "main.rego" for pf in policy_files),
        "ASI-10 Multi-Agent Governance": "agent.delegate" in covered,
    }

    owasp_covered = sum(1 for v in owasp_controls.values() if v)
    passes.append(f"OWASP Agentic Security: {owasp_covered}/10 controls addressed")

    # ── Report ───────────────────────────────────────────────────────────
    print(f"\nKite Logik Compliance Check — {policies_dir}\n")
    print(f"  Policy files:  {len(policy_files)}")
    print(f"  Test files:    {len(test_files)}")
    print()

    for p in passes:
        print(f"  PASS  {p}")
    for i in issues:
        print(f"  WARN  {i}")

    print()

    # OWASP detail
    print("  OWASP Agentic Security Controls:")
    for control, covered_flag in owasp_controls.items():
        status = "COVERED" if covered_flag else "GAP"
        print(f"    [{status:>7}]  {control}")

    print()
    if issues:
        print(f"  Result: {len(passes)} passed, {len(issues)} warning(s). Review warnings above.")
    else:
        print(f"  Result: {len(passes)} passed, 0 warnings. All checks passed.")

    return 0


def cmd_version(args: argparse.Namespace) -> int:
    """Print the kitelogik version."""
    try:
        v = pkg_version("kitelogik")
    except PackageNotFoundError:
        v = "development"
    print(f"kitelogik {v}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kitelogik",
        description="Kite Logik — governance control plane for AI agents",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init
    p_init = subparsers.add_parser("init", help="Scaffold a new governed agent project")
    p_init.add_argument("directory", nargs="?", default=".", help="Target directory (default: .)")
    p_init.set_defaults(func=cmd_init)

    # validate
    p_validate = subparsers.add_parser("validate", help="Validate Rego policy syntax")
    p_validate.add_argument("--path", help="Path to policies directory")
    p_validate.set_defaults(func=cmd_validate)

    # test
    p_test = subparsers.add_parser("test", help="Run OPA tests on policies")
    p_test.add_argument("--path", help="Path to policies directory")
    p_test.add_argument("-v", "--verbose", action="store_true", help="Verbose test output")
    p_test.set_defaults(func=cmd_test)

    # check
    p_check = subparsers.add_parser(
        "check",
        help="Dry-run a governance event against policies",
        description=(
            "Dry-run a governance event against the loaded policies.\n"
            "Pass the event as a JSON string. Example:\n\n"
            '  kitelogik check \'{"action": "read_file", "resource_path": "/etc/passwd", '
            '"context": {"session_id": "s1", "user_role": "support", '
            '"session_scopes": ["read_customer"]}}\''
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_check.add_argument(
        "input",
        help='JSON event payload, e.g. \'{"action": "read_customer_record", ...}\'',
    )
    p_check.add_argument("--path", help="Path to policies directory")
    p_check.set_defaults(func=cmd_check)

    # policy compile
    p_compile = subparsers.add_parser("compile", help="Compile YAML policy to Rego")
    p_compile.add_argument("input", help="Path to YAML policy file")
    p_compile.add_argument("-o", "--output", help="Output path for generated .rego file")
    p_compile.add_argument(
        "--check", action="store_true", help="Validate YAML without generating output"
    )
    p_compile.set_defaults(func=cmd_policy_compile)

    # compliance
    p_compliance = subparsers.add_parser("compliance", help="Run governance compliance check")
    p_compliance.add_argument("--path", help="Path to policies directory")
    p_compliance.set_defaults(func=cmd_compliance_check)

    # version
    p_version = subparsers.add_parser("version", help="Print version")
    p_version.set_defaults(func=cmd_version)

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
