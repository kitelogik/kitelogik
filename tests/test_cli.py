# SPDX-License-Identifier: Apache-2.0
"""Tests for the kitelogik CLI."""

from kitelogik.cli import main


def test_cli_version():
    """kitelogik version prints version string."""
    result = main(["version"])
    assert result == 0


def test_cli_no_command(capsys):
    """kitelogik with no args shows help."""
    result = main([])
    assert result == 0
    captured = capsys.readouterr()
    assert "governance" in captured.out.lower() or "kitelogik" in captured.out.lower()


def test_cli_validate_missing_dir(capsys):
    """kitelogik validate with nonexistent path returns error."""
    result = main(["validate", "--path", "/nonexistent/path"])
    assert result == 1


def test_cli_test_missing_dir(capsys):
    """kitelogik test with nonexistent path returns error."""
    result = main(["test", "--path", "/nonexistent/path"])
    assert result == 1


def test_cli_check_invalid_json(capsys):
    """kitelogik check with invalid JSON returns error."""
    result = main(["check", "not-json"])
    assert result == 1
