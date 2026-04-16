# SPDX-License-Identifier: Apache-2.0
"""
Tests for kitelogik/policy_tester.py.

Verifies:
  - Package name parsing from Rego source
  - Package path → URL path conversion
  - Input loading from JSON string and file
  - CLI --help exits 0
  - Full run with mocked OPA HTTP calls
"""

import json
import subprocess
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kitelogik.policy_tester import _load_input, _package_to_url_path, _parse_package

# ── Unit tests ─────────────────────────────────────────────────────────────────


def test_parse_package_simple():
    rego = "package kitelogik.financial\n\ndefault allow := false\n"
    assert _parse_package(rego) == "kitelogik.financial"


def test_parse_package_with_leading_whitespace():
    rego = "  package   kitelogik.security  \n\ndefault deny := false\n"
    assert _parse_package(rego) == "kitelogik.security"


def test_parse_package_missing_raises():
    rego = "# no package declaration here\ndefault allow := false\n"
    with pytest.raises(ValueError, match="package"):
        _parse_package(rego)


def test_package_to_url_path_dots_to_slashes():
    assert _package_to_url_path("kitelogik.financial") == "kitelogik/financial"


def test_package_to_url_path_single_segment():
    assert _package_to_url_path("main") == "main"


def test_package_to_url_path_three_levels():
    assert _package_to_url_path("a.b.c") == "a/b/c"


def test_load_input_json_string():
    raw = '{"action": "approve_refund", "args": {"amount": 250}}'
    result = _load_input(raw)
    assert result["action"] == "approve_refund"
    assert result["args"]["amount"] == 250


def test_load_input_from_file(tmp_path):
    data = {"action": "list_transactions", "context": {"user_role": "support_agent"}}
    f = tmp_path / "input.json"
    f.write_text(json.dumps(data))
    result = _load_input(str(f))
    assert result["action"] == "list_transactions"


def test_load_input_invalid_json_exits(capsys):
    with pytest.raises(SystemExit):
        _load_input("not valid json {{{")


# ── CLI smoke test ─────────────────────────────────────────────────────────────


def test_cli_help_exits_zero():
    result = subprocess.run(
        [sys.executable, "-m", "kitelogik.policy_tester", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--policy" in result.stdout
    assert "--input" in result.stdout


def test_cli_missing_required_args_exits_nonzero():
    result = subprocess.run(
        [sys.executable, "-m", "kitelogik.policy_tester"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_cli_nonexistent_policy_exits_nonzero():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "kitelogik.policy_tester",
            "--policy",
            "/nonexistent/policy.rego",
            "--input",
            "{}",
            "--opa",
            "http://localhost:9999",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


# ── Integration: mocked OPA HTTP ───────────────────────────────────────────────


@pytest.mark.anyio
async def test_run_with_mocked_opa(tmp_path):
    from kitelogik.policy_tester import run

    rego = "package kitelogik.test_policy\n\ndefault allow := false\nallow if { input.ok }\n"
    policy_file = tmp_path / "test.rego"
    policy_file.write_text(rego)

    input_data = {"ok": True}

    # Mock the httpx.AsyncClient used inside run()
    mock_response_put = MagicMock()
    mock_response_put.status_code = 200

    mock_response_post = MagicMock()
    mock_response_post.status_code = 200
    mock_response_post.raise_for_status = MagicMock()
    mock_response_post.json = MagicMock(return_value={"result": {"allow": True}})

    mock_response_delete = MagicMock()
    mock_response_delete.status_code = 200

    mock_client = AsyncMock()
    mock_client.put = AsyncMock(return_value=mock_response_put)
    mock_client.post = AsyncMock(return_value=mock_response_post)
    mock_client.delete = AsyncMock(return_value=mock_response_delete)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("kitelogik.policy_tester.httpx.AsyncClient", return_value=mock_client):
        exit_code = await run(str(policy_file), input_data, "http://localhost:8181")

    assert exit_code == 0  # allow=True → exit 0
    # Verify OPA was called: PUT to load policy, POST to evaluate, DELETE to clean up
    mock_client.put.assert_called_once()
    mock_client.post.assert_called_once()
    mock_client.delete.assert_called_once()
