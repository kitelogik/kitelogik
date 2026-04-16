# SPDX-License-Identifier: Apache-2.0
"""Pydantic models for the YAML policy format.

Defines the schema for YAML rules that compile to Rego via ``compiler.py``.
The v1 format supports action allowlists, argument thresholds, role/scope
checks, and risk tier assignment.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Condition(BaseModel):
    """A single condition in a policy rule's ``when`` clause.

    Each field maps to a Rego expression. All specified fields must match
    (logical AND).
    """

    action: str | list[str] | None = None
    role: str | list[str] | None = None
    scope: str | list[str] | None = None
    args: dict[str, dict[str, float | int | str | list[str]]] | None = None

    @field_validator("args")
    @classmethod
    def validate_args_operators(cls, v: dict | None) -> dict | None:
        if v is None:
            return v
        valid_ops = {"gt", "gte", "lt", "lte", "eq", "in", "not_in", "contains", "not_contains"}
        for field_name, ops in v.items():
            for op in ops:
                if op not in valid_ops:
                    raise ValueError(
                        f"Unknown operator '{op}' for args.{field_name}. "
                        f"Valid operators: {', '.join(sorted(valid_ops))}"
                    )
        return v


class Rule(BaseModel):
    """A single policy rule in the YAML format."""

    name: str = Field(..., pattern=r"^[a-z][a-z0-9_]{0,63}$")
    when: Condition
    then: Literal["allow", "deny"] = "deny"
    reason: str = ""
    risk_tier: str | None = None


class PolicyFile(BaseModel):
    """Top-level schema for a YAML policy file."""

    version: int = 1
    package: str = Field(..., pattern=r"^[a-z][a-z0-9_.]*$")
    rules: list[Rule] = Field(..., min_length=1)
