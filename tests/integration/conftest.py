# SPDX-License-Identifier: Apache-2.0
"""
Shared fixtures for integration tests.

Starts a real OPA server via Docker (session-scoped) and provides a real
PolicyGate connected to it. All enforcement in integration tests runs against
the actual Rego policies — nothing on the enforcement path is mocked.
"""

import subprocess
import time
from pathlib import Path

import httpx
import pytest

from kitelogik.tether.gate import PolicyGate
from kitelogik.tether.opa_client import OPAClient

POLICIES_DIR = Path(__file__).parent.parent.parent / "policies"
OPA_E2E_PORT = 18182  # Different from adversarial port (18181) to allow parallel runs


def _docker_available() -> bool:
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:
        return False


requires_docker = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker daemon not available",
)


@pytest.fixture(scope="session")
def opa_server():
    container_name = "kitelogik-opa-e2e-test"
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)

    proc = subprocess.Popen(
        [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "-p",
            f"{OPA_E2E_PORT}:8181",
            "-v",
            f"{POLICIES_DIR.resolve()}:/policies:ro",
            "openpolicyagent/opa:latest",
            "run",
            "--server",
            "--addr",
            ":8181",
            "--watch",
            "/policies",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    base_url = f"http://localhost:{OPA_E2E_PORT}"
    deadline = time.monotonic() + 20.0
    last_exc = None

    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{base_url}/health", timeout=1.0)
            if r.status_code == 200:
                break
        except Exception as exc:
            last_exc = exc
        time.sleep(0.5)
    else:
        proc.terminate()
        proc.wait()
        pytest.fail(f"OPA e2e server did not become healthy within 20s: {last_exc}")

    yield base_url

    proc.terminate()
    proc.wait()


@pytest.fixture(scope="session")
def real_gate(opa_server: str) -> PolicyGate:
    opa = OPAClient(base_url=opa_server)
    return PolicyGate(opa_client=opa)
