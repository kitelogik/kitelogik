# SPDX-License-Identifier: Apache-2.0
import asyncio
import logging
import threading
from urllib.parse import urlparse

import httpx

from .models import GovernanceEvent, PolicyDecision, PolicyInput, result_to_decision

logger = logging.getLogger(__name__)

_OPA_RECOVERY_HINT = (
    "Start OPA locally with `docker compose up -d opa`, "
    "or pass base_url=... to OPAClient pointing at your bundle server."
)


class OPAConnectionError(Exception):
    """Raised when the OPA server cannot be reached or returns an error."""


class OPAClient:
    """Async client for the Open Policy Agent REST API.

    OPA must be running and serving the kitelogik policy bundle.
    The underlying httpx client is created lazily on first use so it is
    always bound to the current event loop — safe across pytest test
    boundaries and framework restarts.

    Parameters
    ----------
    base_url : str
            OPA server URL. Must use ``http://`` or ``https://`` scheme.
    """

    def __init__(self, base_url: str = "http://localhost:8181") -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"OPA base_url must use http:// or https:// scheme, got {parsed.scheme!r}"
            )
        self.base_url = base_url.rstrip("/")
        self._package_path = "kitelogik/main"
        self._client: httpx.AsyncClient | None = None
        self._client_loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

    def _get_client(self) -> httpx.AsyncClient:
        """Return (or lazily create) an httpx client bound to the running loop.

        Thread-safe: a lock guards client creation so concurrent threads
        (e.g. via ``_run_coroutine_sync``) do not race on ``_client``.
        """
        loop = asyncio.get_running_loop()
        with self._lock:
            if self._client is None or self._client_loop is not loop:
                # Discard stale client from a previous event loop (best-effort).
                # The old loop is typically closed (pytest boundary), so we
                # cannot schedule async cleanup on it — just drop the reference.
                self._client = httpx.AsyncClient(base_url=self.base_url, timeout=5.0)
                self._client_loop = loop
            return self._client

    async def aclose(self) -> None:
        """Close the underlying HTTP client. Call on shutdown."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
            self._client_loop = None

    async def __aenter__(self) -> "OPAClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def health(self) -> bool:
        """Return True if OPA is reachable and healthy."""
        try:
            r = await self._get_client().get("/health", timeout=2.0)
            if not r.is_success:
                logger.warning("OPA health check returned HTTP %d", r.status_code)
            return r.is_success
        except httpx.ConnectError as exc:
            logger.warning("OPA unreachable (connection refused): %s", exc)
            return False
        except httpx.TimeoutException as exc:
            logger.warning("OPA health check timed out: %s", exc)
            return False
        except httpx.HTTPError as exc:
            logger.error("OPA health check unexpected error: %s", exc)
            return False

    async def _post_to_opa(self, input_data: dict) -> dict:
        """Post input to OPA and return the result dict.

        Raises
        ------
        OPAConnectionError
                If OPA is unreachable or returns a non-200 response.
        """
        payload = {"input": input_data}

        try:
            response = await self._get_client().post(
                f"/v1/data/{self._package_path}",
                json=payload,
            )
            response.raise_for_status()
        except httpx.ConnectError as exc:
            raise OPAConnectionError(
                f"Cannot reach OPA at {self.base_url}. {_OPA_RECOVERY_HINT}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise OPAConnectionError(
                f"OPA request to {self.base_url} timed out after 5s. "
                f"Check OPA is reachable and not overloaded. {_OPA_RECOVERY_HINT}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise OPAConnectionError(
                f"OPA returned HTTP {exc.response.status_code} from {self.base_url}: "
                f"{exc.response.text}. "
                "Check the policy bundle is loaded and the kitelogik/main package is present."
            ) from exc

        return dict(response.json().get("result", {}))

    async def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        """Evaluate a tool call against the ``kitelogik.main`` policy package.

        Raises
        ------
        OPAConnectionError
                If OPA is unreachable or returns a non-200 response.
        """
        result = await self._post_to_opa(policy_input.model_dump())
        return result_to_decision(result)

    async def evaluate_event(self, event: GovernanceEvent) -> PolicyDecision:
        """Evaluate a governance event against the ``kitelogik.main`` policy package.

        Supports all event types: ``tool_call``, ``agent.spawn``,
        ``agent.delegate``, ``agent.plan``, ``agent.budget``.

        Raises
        ------
        OPAConnectionError
                If OPA is unreachable or returns a non-200 response.
        """
        result = await self._post_to_opa(event.model_dump())
        return result_to_decision(result)
