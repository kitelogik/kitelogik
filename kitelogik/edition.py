# SPDX-License-Identifier: Apache-2.0
"""
Edition detection and enterprise plugin discovery.

How it works
------------
The enterprise package (`kitelogik-enterprise`) registers concrete
implementations against named entry-point groups defined here.  The OSS
package never imports enterprise code directly — it calls the factory
functions below and gets back either the OSS default or the enterprise
override, depending on what is installed.

Entry-point groups (defined in kitelogik-enterprise's pyproject.toml)
----------------------------------------------------------------------
    kitelogik.sandbox_runtime   → class with same interface as DockerRuntime
    kitelogik.memory_backend    → class with same interface as MemoryStore
    kitelogik.hitl_backend      → class with same interface as HITLQueue
    kitelogik.credential_broker → class with same interface as CredentialBroker
    kitelogik.audit_backend     → class with same interface as AuditStore

Usage (inside OSS factory functions)
--------------------------------------
    from kitelogik.edition import edition, Edition, load_plugin

    runtime_cls = load_plugin("kitelogik.sandbox_runtime") or DockerRuntime

Checking edition in application code
--------------------------------------
    from kitelogik.edition import edition, Edition

    if edition() is Edition.ENTERPRISE:
        ...  # adjust behaviour for enterprise deployments

    # Or, for a specific capability check:
    if load_plugin("kitelogik.sandbox_runtime") is not None:
        ...  # Firecracker is available
"""

from __future__ import annotations

from enum import StrEnum
from importlib.metadata import entry_points
from typing import Any


class Edition(StrEnum):
    OSS = "oss"
    ENTERPRISE = "enterprise"


def edition() -> Edition:
    """
    Return the running edition.

    Enterprise is detected by the presence of *any* registered plugin in the
    kitelogik.* entry-point namespace — i.e. whether kitelogik-enterprise (or
    any licensed extension) has been installed alongside this package.
    """
    groups = [
        "kitelogik.sandbox_runtime",
        "kitelogik.memory_backend",
        "kitelogik.hitl_backend",
        "kitelogik.credential_broker",
        "kitelogik.audit_backend",
    ]
    for group in groups:
        if entry_points(group=group):
            return Edition.ENTERPRISE
    return Edition.OSS


def load_plugin(group: str, name: str = "default") -> Any | None:
    """
    Load the first registered plugin for *group*, or None if none is installed.

    The enterprise package registers plugins as::

            [project.entry-points."kitelogik.sandbox_runtime"]
            default = "kitelogik_enterprise.sandbox.firecracker:FirecrackerRuntime"

    OSS factory functions call this and fall back to the built-in
    implementation when it returns None::

            from kitelogik.edition import load_plugin

            _cls = load_plugin("kitelogik.sandbox_runtime")
            runtime = (_cls or DockerRuntime)(image=image)

    Parameters
    ----------
    group : str
            The entry-point group, e.g. ``"kitelogik.sandbox_runtime"``.
    name : str
            The specific entry-point name within the group.  Defaults to
            ``"default"`` — enterprise plugins should register under this name
            unless multiple implementations are offered.

    Returns
    -------
    Any | None
            The loaded plugin object (class, function, or instance), or ``None``.
    """
    eps = entry_points(group=group)
    # entry_points() returns a SelectableGroups mapping; .select() works in 3.12+
    # Iterate for compatibility.
    for ep in eps:
        if ep.name == name:
            return ep.load()
    # If no "default" named entry point, return the first registered one.
    for ep in eps:
        return ep.load()
    return None
