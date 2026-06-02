# SPDX-License-Identifier: Apache-2.0
"""Tests for the industry starter templates in kitelogik/policy_templates.

These compile each template and assert the threat-model-critical rules are
present in the generated Rego. They run without OPA — end-to-end decision
behaviour against the full bundle is verified separately with `opa test`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kitelogik.policies.compiler import compile_yaml
from kitelogik.policies.schema import PolicyFile

_TEMPLATES_DIR = Path(__file__).parent.parent / "kitelogik" / "policy_templates"
_TEMPLATES = sorted(_TEMPLATES_DIR.glob("*.yaml"))
_IDS = [p.stem for p in _TEMPLATES]


def test_three_templates_ship():
    assert _IDS == [
        "code-execution-restrictions",
        "financial-refunds",
        "healthcare-phi-access",
    ]


@pytest.mark.parametrize("path", _TEMPLATES, ids=_IDS)
def test_template_is_valid_schema(path: Path):
    import yaml

    PolicyFile.model_validate(yaml.safe_load(path.read_text()))


@pytest.mark.parametrize("path", _TEMPLATES, ids=_IDS)
def test_template_compiles_to_userpolicy(path: Path):
    rego = compile_yaml(path)
    assert "package kitelogik.userpolicy" in rego
    # Merge-safe: no defaults (the userpolicy.rego stub owns them).
    assert "default " not in rego


def test_financial_refunds_rules():
    rego = compile_yaml(_TEMPLATES_DIR / "financial-refunds.yaml")
    assert "input.args.amount <= 50" in rego  # small → allow
    assert 'hitl["Refunds between 50 and 500 require a human reviewer"]' in rego
    assert "input.args.amount > 500" in rego  # large → deny
    assert 'input.args.destination_country in {"IR", "KP", "SY", "RU"}' in rego


def test_healthcare_phi_rules():
    rego = compile_yaml(_TEMPLATES_DIR / "healthcare-phi-access.yaml")
    assert 'hitl["Record changes need sign-off from a registered clinician"]' in rego
    # Special-category queries are a hard deny, never HITL.
    assert 'deny["Special-category data (GDPR Art. 9 / EU AI Act) is off-limits"]' in rego
    assert "hiv_status" in rego


def test_code_execution_rules():
    rego = compile_yaml(_TEMPLATES_DIR / "code-execution-restrictions.yaml")
    assert 'deny["Direct shell and eval access is never permitted for agents"]' in rego
    assert 'contains(input.args.path, "/workspace/")' in rego
    assert 'not contains(input.args.path, "/workspace/")' in rego
