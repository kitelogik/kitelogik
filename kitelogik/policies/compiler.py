# SPDX-License-Identifier: Apache-2.0
"""YAML -> Rego policy compiler.

Compiles declarative YAML rules into valid Rego policies that work with
both OPA (HTTP) and Regorus (in-process). The generated Rego follows the
same conventions as hand-written policies in ``policies/``.

v1 scope:
    - Action allowlists / denylists
    - Argument thresholds (gt, gte, lt, lte, eq)
    - Role and scope checks
    - Risk tier assignment
    - Deny reasons

Complex interactions (delegation cascades, plan evaluation, data classification)
should remain in hand-written Rego.

Usage::

    from kitelogik.policies.compiler import compile_yaml

    rego_source = compile_yaml("policies/examples/example_rules.yaml")
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from .schema import Condition, PolicyFile, Rule

logger = logging.getLogger(__name__)

# Rego operator mapping
_ARG_OPS = {
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
    "eq": "==",
}

# Every compiled policy lands here. main.rego aggregates this package's
# allow / deny / hitl; the hand-written userpolicy.rego stub owns the
# defaults so compiled output can stay merge-safe (defaults-free).
USERPOLICY_PACKAGE = "kitelogik.userpolicy"


def compile_yaml(path: str | Path) -> str:
    """Compile a YAML policy file into Rego source.

    Parameters
    ----------
    path : str | Path
            Path to the YAML policy file.

    Returns
    -------
    str
            Generated Rego source code as a string.

    Raises
    ------
    FileNotFoundError
            If the YAML file doesn't exist.
    ValueError
            If the YAML is invalid or doesn't match the schema.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"Expected a YAML mapping, got {type(raw).__name__}")

    policy = PolicyFile.model_validate(raw)
    return _render_rego(policy)


def compile_yaml_string(source: str) -> str:
    """Compile YAML policy source (string) into Rego source.

    Parameters
    ----------
    source : str
            YAML policy content as a string.

    Returns
    -------
    str
            Generated Rego source code as a string.
    """
    raw = yaml.safe_load(source)
    if not isinstance(raw, dict):
        raise ValueError(f"Expected a YAML mapping, got {type(raw).__name__}")

    policy = PolicyFile.model_validate(raw)
    return _render_rego(policy)


def _render_rego(policy: PolicyFile) -> str:
    """Render a validated PolicyFile into Rego source.

    Output is merge-safe: it targets the shared ``kitelogik.userpolicy``
    package and declares no ``default`` values, so any number of compiled
    files union cleanly with each other and with the hand-written
    ``userpolicy.rego`` stub (which owns the defaults). ``allow`` is
    incremental; ``deny`` and ``hitl`` are always set-valued so they
    never collide with a boolean default in another file.
    """
    lines: list[str] = []

    lines.append(f"package {USERPOLICY_PACKAGE}")
    lines.append("")
    lines.append("import future.keywords.if")
    lines.append("import future.keywords.in")
    lines.append("")

    for rule in policy.rules:
        lines.extend(_render_rule(rule))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_rule(rule: Rule) -> list[str]:
    """Render a single Rule into Rego lines."""
    lines: list[str] = []

    # Comment with rule name and reason
    comment = f"# {rule.name}"
    if rule.reason:
        comment += f": {rule.reason}"
    lines.append(comment)

    # deny and hitl are always set-valued — the key is the reason when
    # present, else the rule name. Set-valued rules union across files
    # and never conflict with a boolean default, which is what keeps
    # multiple compiled policies (and the stub) mergeable.
    if rule.then in ("deny", "hitl"):
        key = rule.reason if rule.reason else rule.name
        lines.append(f'{rule.then}["{key}"] if {{')
    else:
        lines.append("allow if {")

    # Conditions
    body_lines = _render_condition(rule.when)
    for bl in body_lines:
        lines.append(f"\t{bl}")

    lines.append("}")

    # Risk tier assignment as a separate rule if specified. Emitted into
    # the userpolicy package but not yet aggregated by main.rego, so a
    # YAML-set risk_tier is currently inert — kept for forward
    # compatibility until risk-tier precedence is wired through.
    if rule.risk_tier:
        lines.append("")
        lines.append(f"# risk tier for {rule.name}")
        lines.append(f'risk_tier := "{rule.risk_tier}" if {{')
        for bl in _render_condition(rule.when):
            lines.append(f"\t{bl}")
        lines.append("}")

    return lines


def _render_condition(cond: Condition) -> list[str]:
    """Render a Condition into Rego body lines (without indentation)."""
    lines: list[str] = []

    # Action check
    if cond.action is not None:
        if isinstance(cond.action, list):
            actions_set = ", ".join(f'"{a}"' for a in cond.action)
            lines.append(f"input.action in {{{actions_set}}}")
        else:
            lines.append(f'input.action == "{cond.action}"')

    # Role check
    if cond.role is not None:
        if isinstance(cond.role, list):
            roles_set = ", ".join(f'"{r}"' for r in cond.role)
            lines.append(f"input.context.user_role in {{{roles_set}}}")
        else:
            lines.append(f'input.context.user_role == "{cond.role}"')

    # Scope check
    if cond.scope is not None:
        if isinstance(cond.scope, list):
            for s in cond.scope:
                lines.append(f'"{s}" in input.context.session_scopes')
        else:
            lines.append(f'"{cond.scope}" in input.context.session_scopes')

    # Args checks
    if cond.args:
        for field_name, ops in cond.args.items():
            rego_field = f"input.args.{field_name}"
            for op, value in ops.items():
                if op == "in":
                    if isinstance(value, list):
                        vals = ", ".join(f'"{v}"' for v in value)
                        lines.append(f"{rego_field} in {{{vals}}}")
                    else:
                        lines.append(f'{rego_field} in {{"{value}"}}')
                elif op == "not_in":
                    if isinstance(value, list):
                        vals = ", ".join(f'"{v}"' for v in value)
                        lines.append(f"not {rego_field} in {{{vals}}}")
                    else:
                        lines.append(f'not {rego_field} in {{"{value}"}}')
                elif op == "contains":
                    lines.append(f'contains({rego_field}, "{value}")')
                elif op == "not_contains":
                    lines.append(f'not contains({rego_field}, "{value}")')
                elif op in _ARG_OPS:
                    if isinstance(value, str):
                        lines.append(f'{rego_field} {_ARG_OPS[op]} "{value}"')
                    else:
                        lines.append(f"{rego_field} {_ARG_OPS[op]} {value}")
                else:
                    raise ValueError(f"Unknown operator: {op}")

    return lines
