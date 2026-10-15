"""HTTP transport selection for the discovery-based GCP collectors.

Why this module exists
----------------------
``googleapiclient.discovery.build(..., credentials=...)`` routes every request
through ``google-auth-httplib2``, i.e. over **httplib2**. That default caused two
operational problems:

* **No per-request timeout worth the name.** ``httplib2`` takes its timeout when
  the ``Http`` object is built, so a stalled socket turns a scan into an
  indefinite wait and ``google-auth-httplib2`` only logs *"httplib2 transport
  does not support per-request timeout"* when asked for one.
* **It is not the transport the rest of the toolchain uses.** ``gcloud``, ADC and
  every ``google-cloud-*`` client speak HTTP through ``requests``. In locked-down
  environments (Cloud Workstations, proxy/CA bundles, IPv6-only egress) we have
  seen ``requests`` reach the API in under a second while ``httplib2`` timed out
  against the very same endpoint. The 12 discovery collectors then collected
  nothing and the scan still reported "no findings".

Therefore the default transport is now ``requests`` — through
``google.auth.transport.requests.AuthorizedSession``, which keeps credential
refresh — with an explicit timeout per request. ``--transport httplib2`` restores
the legacy behaviour for the rare environment where httplib2 is the one that
works.

Collectors never import this module directly: they call
``BaseCollector.build_client()``, which records the failure as a coverage gap when
the client cannot be built.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

#: Per-request timeout (seconds) used when neither the CLI nor the environment
#: specifies one. 30 s is generous for a control-plane read and keeps the worst
#: case (one stalled socket × every collector) inside a bounded scan.
DEFAULT_TIMEOUT: float = 30.0

#: Environment override for ``--transport`` (handy in CI/Docker images).
TRANSPORT_ENV_VAR = "GCP_ABUSE_SCANNER_TRANSPORT"

#: Accepted transport names.
TRANSPORTS: tuple[str, ...] = ("requests", "httplib2")

DEFAULT_TRANSPORT = "requests"


class TransportError(RuntimeError):
    """A transport-level failure (timeout, DNS, TLS, proxy, connection reset).

    Distinct from an API error: nothing was read from GCP, so the affected check
    has no data. Collectors record it as a coverage gap
    (``inventory.collector_errors``) instead of swallowing it.
    """


def resolve_transport(transport: str | None) -> str:
    """Return the transport to use: explicit value > env var > default."""
    chosen = transport or os.environ.get(TRANSPORT_ENV_VAR) or DEFAULT_TRANSPORT
    chosen = chosen.strip().lower()
    if chosen not in TRANSPORTS:
        raise ValueError(f"Unknown transport {chosen!r} — expected one of: {', '.join(TRANSPORTS)}")
    return chosen


def _host(uri: str) -> str:
    return urlsplit(uri).netloc or uri


class Response(dict):
    """httplib2-shaped response: a mapping of headers plus ``.status``/``.reason``.

    ``googleapiclient`` reads ``resp.status``, formats errors with ``resp.reason``
    and does header lookups with ``resp["content-encoding"]``, so both the
    attribute and the mapping interfaces have to work.
    """

    def __init__(self, status: int, reason: str = "", headers: Any = None) -> None:
        super().__init__({str(k).lower(): v for k, v in dict(headers or {}).items()})
        self.status = status
        self.reason = reason or ""


class RequestsTransport:
    """Minimal ``httplib2.Http``-compatible adapter backed by ``requests``.

    ``googleapiclient`` only requires an object with
    ``request(uri, method, body, headers, ...) -> (response, bytes)``, which is
    what this class implements on top of ``google.auth.transport.requests``
    (``AuthorizedSession`` when credentials are given, so token refresh is
    handled for us).
    """

    def __init__(
        self,
        credentials: Any = None,
        timeout: float | None = None,
        session: Any = None,
    ) -> None:
        self.timeout = DEFAULT_TIMEOUT if timeout is None else timeout
        self.credentials = credentials
        if session is None:
            if credentials is not None:
                from google.auth.transport.requests import AuthorizedSession

                session = AuthorizedSession(credentials)
            else:
                import requests

                session = requests.Session()
        self._session = session

    def request(
        self,
        uri: str,
        method: str = "GET",
        body: Any = None,
        headers: Any = None,
        redirections: int = 5,
        connection_type: Any = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> tuple[Response, bytes]:
        """Perform one HTTP request and return ``(response, body_bytes)``."""
        import requests

        effective = self.timeout if timeout is None else timeout
        # 0 means "no timeout" — pass None so requests waits indefinitely.
        request_timeout = effective or None
        try:
            resp = self._session.request(
                method,
                uri,
                data=body,
                headers={str(k): str(v) for k, v in dict(headers or {}).items()},
                timeout=request_timeout,
                allow_redirects=bool(redirections),
            )
        except requests.exceptions.Timeout as exc:
            raise TransportError(
                f"transport timeout after {effective:g}s for {method} {_host(uri)} "
                f"(requests transport) — no data collected"
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise TransportError(
                f"transport error for {method} {_host(uri)} (requests transport): {exc}"
            ) from exc
        return Response(resp.status_code, reason=resp.reason, headers=resp.headers), resp.content

    def close(self) -> None:
        """Close the underlying session (httplib2.Http.close compatibility)."""
        self._session.close()


def build_http(
    credentials: Any = None,
    timeout: float | None = None,
    transport: str | None = None,
) -> Any:
    """Return an authorized http object for the requested transport.

    The result is dropped straight into ``googleapiclient.discovery.build(http=…)``.
    """
    chosen = resolve_transport(transport)
    effective = DEFAULT_TIMEOUT if timeout is None else timeout

    if chosen == "requests":
        return RequestsTransport(credentials, timeout=effective)

    # ── legacy httplib2 transport (still bounded by an explicit timeout) ──────
    import google_auth_httplib2
    import httplib2

    if effective:
        http = httplib2.Http(timeout=effective)
    else:  # pragma: no cover — only when the caller explicitly asks for no limit
        from googleapiclient.http import build_http as _default_http

        http = _default_http()

    if credentials is None:
        # AuthorizedHttp(None) builds fine but raises AttributeError on
        # `credentials.before_request` for every request, so keep the anonymous
        # client unwrapped (mirrors the requests branch with credentials=None).
        logger.debug(
            "Using anonymous httplib2 transport (timeout=%s)", effective or "library default"
        )
        return http

    logger.debug("Using httplib2 transport (timeout=%s)", effective or "library default")
    return google_auth_httplib2.AuthorizedHttp(credentials, http=http)


def build_service(
    api: str,
    version: str,
    credentials: Any = None,
    timeout: float | None = None,
    transport: str | None = None,
) -> Any:
    """Build a discovery client for ``api``/``version`` over the chosen transport.

    Raises ``ValueError`` for an unknown transport name and propagates any error
    from ``googleapiclient`` (the caller records it as a coverage gap).
    """
    import googleapiclient.discovery

    http = build_http(credentials=credentials, timeout=timeout, transport=transport)
    logger.debug(
        "Building %s/%s client over %s transport (timeout=%ss)",
        api,
        version,
        resolve_transport(transport),
        timeout if timeout is not None else DEFAULT_TIMEOUT,
    )
    return googleapiclient.discovery.build(api, version, http=http)
