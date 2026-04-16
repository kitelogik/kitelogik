# SPDX-License-Identifier: Apache-2.0
"""Tests for the YAML -> Rego policy compiler."""

from __future__ import annotations

from pathlib import Path

import pytest

from kitelogik.policies.compiler import compile_yaml, compile_yaml_string
from kitelogik.policies.schema import PolicyFile, Rule

# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


class TestPolicySchema:
    def test_valid_policy_file(self):
        pf = PolicyFile(
            version=1,
            package="kitelogik.custom",
            rules=[
                Rule(
                    name="block_high_refunds",
                    when={"action": "approve_refund", "args": {"amount": {"gt": 1000}}},
                    then="deny",
                    reason="Too high",
                ),
            ],
        )
        assert len(pf.rules) == 1

    def test_invalid_rule_name(self):
        with pytest.raises(Exception):
            Rule(
                name="Invalid-Name!",
                when={"action": "test"},
                then="allow",
            )

    def test_invalid_package_name(self):
        with pytest.raises(Exception):
            PolicyFile(
                version=1,
                package="Invalid Package",
                rules=[
                    Rule(name="test_rule", when={"action": "test"}, then="allow"),
                ],
            )

    def test_empty_rules_rejected(self):
        with pytest.raises(Exception):
            PolicyFile(version=1, package="kitelogik.test", rules=[])

    def test_invalid_args_operator(self):
        with pytest.raises(ValueError, match="Unknown operator"):
            Rule(
                name="bad_operator",
                when={"action": "test", "args": {"amount": {"invalid_op": 100}}},
                then="deny",
            )


# ---------------------------------------------------------------------------
# Compiler output
# ---------------------------------------------------------------------------


class TestCompileYamlString:
    def test_simple_deny_rule(self):
        yaml_src = """
version: 1
package: kitelogik.test
rules:
  - name: block_dangerous
    when:
      action: delete_database
    then: deny
    reason: "Database deletion not permitted"
"""
        rego = compile_yaml_string(yaml_src)
        assert "package kitelogik.test" in rego
        assert "import future.keywords.if" in rego
        # Deny rules with reasons compile to set-valued deny[msg],
        # which needs no boolean default (empty set is the default).
        assert "default deny := false" not in rego
        assert '"Database deletion not permitted"' in rego
        assert 'input.action == "delete_database"' in rego

    def test_simple_allow_rule(self):
        yaml_src = """
version: 1
package: kitelogik.test
rules:
  - name: allow_reads
    when:
      action:
        - read_customer
        - list_transactions
      scope: read_customer
    then: allow
    risk_tier: INFORMATIONAL
"""
        rego = compile_yaml_string(yaml_src)
        assert "default allow := false" in rego
        assert "allow if {" in rego
        assert 'input.action in {"read_customer", "list_transactions"}' in rego
        assert '"read_customer" in input.context.session_scopes' in rego
        assert 'risk_tier := "INFORMATIONAL"' in rego

    def test_role_check(self):
        yaml_src = """
version: 1
package: kitelogik.test
rules:
  - name: managers_only
    when:
      action: approve_refund
      role: manager
    then: allow
"""
        rego = compile_yaml_string(yaml_src)
        assert 'input.context.user_role == "manager"' in rego

    def test_multiple_roles(self):
        yaml_src = """
version: 1
package: kitelogik.test
rules:
  - name: support_or_manager
    when:
      action: approve_refund
      role:
        - support_agent
        - manager
    then: allow
"""
        rego = compile_yaml_string(yaml_src)
        assert 'input.context.user_role in {"support_agent", "manager"}' in rego

    def test_arg_threshold(self):
        yaml_src = """
version: 1
package: kitelogik.test
rules:
  - name: block_high_amount
    when:
      action: approve_refund
      args:
        amount:
          gt: 1000
    then: deny
    reason: "Amount too high"
"""
        rego = compile_yaml_string(yaml_src)
        assert "input.args.amount > 1000" in rego

    def test_arg_range(self):
        yaml_src = """
version: 1
package: kitelogik.test
rules:
  - name: allow_small_refund
    when:
      action: approve_refund
      args:
        amount:
          gte: 0
          lte: 100
    then: allow
"""
        rego = compile_yaml_string(yaml_src)
        assert "input.args.amount >= 0" in rego
        assert "input.args.amount <= 100" in rego

    def test_arg_in_list(self):
        yaml_src = """
version: 1
package: kitelogik.test
rules:
  - name: allowed_categories
    when:
      action: process_order
      args:
        category:
          in:
            - electronics
            - books
    then: allow
"""
        rego = compile_yaml_string(yaml_src)
        assert 'input.args.category in {"electronics", "books"}' in rego

    def test_arg_not_in_list(self):
        yaml_src = """
version: 1
package: kitelogik.test
rules:
  - name: block_restricted_paths
    when:
      action: write_file
      args:
        path:
          not_in:
            - /etc
            - /var
    then: deny
    reason: "Restricted path"
"""
        rego = compile_yaml_string(yaml_src)
        assert 'not input.args.path in {"/etc", "/var"}' in rego

    def test_multiple_scopes(self):
        yaml_src = """
version: 1
package: kitelogik.test
rules:
  - name: needs_both_scopes
    when:
      action: transfer_funds
      scope:
        - transfer
        - write_account
    then: allow
"""
        rego = compile_yaml_string(yaml_src)
        assert '"transfer" in input.context.session_scopes' in rego
        assert '"write_account" in input.context.session_scopes' in rego

    def test_mixed_allow_and_deny(self):
        yaml_src = """
version: 1
package: kitelogik.test
rules:
  - name: allow_reads
    when:
      action: read_data
    then: allow
  - name: block_deletes
    when:
      action: delete_data
    then: deny
    reason: "No deletions"
"""
        rego = compile_yaml_string(yaml_src)
        assert "default allow := false" in rego
        # deny[msg] is set-valued — no boolean default needed
        assert "default deny := false" not in rego
        assert "allow if {" in rego
        assert 'deny["No deletions"] if {' in rego

    def test_invalid_yaml_type_raises(self):
        with pytest.raises(ValueError, match="Expected a YAML mapping"):
            compile_yaml_string("- just a list")


# ---------------------------------------------------------------------------
# File-based compilation
# ---------------------------------------------------------------------------


class TestCompileYamlFile:
    def test_compile_example_file(self):
        example_path = Path("kitelogik/policies/examples/example_rules.yaml")
        if not example_path.exists():
            pytest.skip("Example YAML not found")

        rego = compile_yaml(example_path)
        assert "package kitelogik.custom_rules" in rego
        assert "block_high_refunds" in rego
        assert "allow_read_ops" in rego

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            compile_yaml("nonexistent.yaml")

    def test_compile_to_output_file(self, tmp_path):
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text("""
version: 1
package: kitelogik.generated_test
rules:
  - name: test_rule
    when:
      action: test_action
    then: allow
""")
        rego = compile_yaml(yaml_file)
        output = tmp_path / "test.rego"
        output.write_text(rego)

        assert output.exists()
        content = output.read_text()
        assert "package kitelogik.generated_test" in content
