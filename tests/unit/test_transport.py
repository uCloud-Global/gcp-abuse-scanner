"""Unit tests for the HTTP transport selection (requests vs httplib2) and the adapter."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from gcp_abuse_scanner.collectors.base import BaseCollector
from gcp_abuse_scanner.models.inventory import ResourceInventory
from gcp_abuse_scanner.utils.transport import (
    DEFAULT_TIMEOUT,
    TRANSPORT_ENV_VAR,
    RequestsTransport,
    Response,
    TransportError,
    build_http,
    build_service,
    resolve_transport,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


class _StubResponse:
    def __init__(
        self,
        status_code: int = 200,
        payload: bytes = b"{}",
        reason: str = "OK",
        headers: dict | None = None,
    ) -> None:
        self.status_code = status_code
        self.content = payload
        self.reason = reason
        self.headers = headers if headers is not None else {"Content-Type": "application/json"}


class _StubSession:
    """Stands in for requests.Session / AuthorizedSession."""

    def __init__(self, response: _StubResponse | None = None, exc: Exception | None = None):
        self._response = response or _StubResponse()
        self._exc = exc
        self.calls: list[dict] = []
        self.closed = False

    def request(self, method, uri, data=None, headers=None, timeout=None, allow_redirects=True):
        self.calls.append(
            {
                "method": method,
                "uri": uri,
                "data": data,
                "headers": headers,
                "timeout": timeout,
                "allow_redirects": allow_redirects,
            }
        )
        if self._exc is not None:
            raise self._exc
        return self._response

    def close(self) -> None:
        self.closed = True


# ─────────────────────────────────────────────────────────────────────────────
# resolve_transport
# ─────────────────────────────────────────────────────────────────────────────


class TestResolveTransport:
    def test_default_is_requests(self, monkeypatch) -> None:
        monkeypatch.delenv(TRANSPORT_ENV_VAR, raising=False)
        assert resolve_transport(None) == "requests"

    def test_env_var_is_honoured(self, monkeypatch) -> None:
        monkeypatch.setenv(TRANSPORT_ENV_VAR, "httplib2")
        assert resolve_transport(None) == "httplib2"

    def test_explicit_value_beats_env_var(self, monkeypatch) -> None:
        monkeypatch.setenv(TRANSPORT_ENV_VAR, "httplib2")
        assert resolve_transport("requests") == "requests"

    def test_value_is_normalised(self, monkeypatch) -> None:
        monkeypatch.delenv(TRANSPORT_ENV_VAR, raising=False)
        assert resolve_transport("  HTTPLIB2  ") == "httplib2"

    def test_unknown_transport_raises(self, monkeypatch) -> None:
        monkeypatch.delenv(TRANSPORT_ENV_VAR, raising=False)
        with pytest.raises(ValueError, match="Unknown transport"):
            resolve_transport("sockets")

    def test_unknown_env_value_raises(self, monkeypatch) -> None:
        monkeypatch.setenv(TRANSPORT_ENV_VAR, "nope")
        with pytest.raises(ValueError, match="nope"):
            resolve_transport(None)


# ─────────────────────────────────────────────────────────────────────────────
# build_http / build_service
# ─────────────────────────────────────────────────────────────────────────────


class TestBuildHttp:
    def test_requests_transport_is_the_default(self, monkeypatch) -> None:
        monkeypatch.delenv(TRANSPORT_ENV_VAR, raising=False)
        http = build_http()
        assert isinstance(http, RequestsTransport)
        assert http.timeout == DEFAULT_TIMEOUT

    def test_default_transport_is_per_request_timeout_bounded(self, monkeypatch) -> None:
        monkeypatch.delenv(TRANSPORT_ENV_VAR, raising=False)
        assert DEFAULT_TIMEOUT > 0  # httplib2's default made a stalled socket unbounded

    def test_explicit_timeout_is_used(self) -> None:
        assert build_http(timeout=5).timeout == 5

    def test_zero_timeout_means_no_limit(self) -> None:
        assert build_http(timeout=0).timeout == 0

    def test_credentials_build_an_authorized_session(self) -> None:
        creds = MagicMock()
        with patch("google.auth.transport.requests.AuthorizedSession") as mock_session:
            http = build_http(credentials=creds)
        mock_session.assert_called_once_with(creds)
        assert isinstance(http, RequestsTransport)

    def test_httplib2_transport_keeps_an_explicit_timeout(self) -> None:
        with (
            patch("httplib2.Http") as mock_http,
            patch("google_auth_httplib2.AuthorizedHttp") as mock_authorized,
        ):
            result = build_http(credentials=MagicMock(), transport="httplib2", timeout=7)
        mock_http.assert_called_once_with(timeout=7)
        mock_authorized.assert_called_once()
        assert result is mock_authorized.return_value

    def test_httplib2_without_credentials_is_not_wrapped(self) -> None:
        """AuthorizedHttp(None) builds but raises on the first request — don't wrap."""
        with (
            patch("httplib2.Http") as mock_http,
            patch("google_auth_httplib2.AuthorizedHttp") as mock_authorized,
        ):
            result = build_http(credentials=None, transport="httplib2", timeout=7)
        mock_authorized.assert_not_called()
        assert result is mock_http.return_value

    def test_requests_without_credentials_is_anonymous(self) -> None:
        with patch("google.auth.transport.requests.AuthorizedSession") as mock_session:
            http = build_http(credentials=None, timeout=5)
        mock_session.assert_not_called()
        assert isinstance(http, RequestsTransport)

    def test_build_http_rejects_unknown_transport(self) -> None:
        with pytest.raises(ValueError):
            build_http(transport="carrier-pigeon")


class TestBuildService:
    def test_passes_the_transport_to_discovery_build(self, monkeypatch) -> None:
        monkeypatch.delenv(TRANSPORT_ENV_VAR, raising=False)
        with patch("googleapiclient.discovery.build") as mock_build:
            result = build_service("compute", "v1", credentials=MagicMock(), timeout=12)
        assert result is mock_build.return_value
        _, kwargs = mock_build.call_args
        assert isinstance(kwargs["http"], RequestsTransport)
        assert kwargs["http"].timeout == 12

    def test_unknown_transport_raises_before_any_request(self) -> None:
        with patch("googleapiclient.discovery.build") as mock_build:
            with pytest.raises(ValueError):
                build_service("compute", "v1", transport="bogus")
        mock_build.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# RequestsTransport adapter
# ─────────────────────────────────────────────────────────────────────────────


class TestRequestsTransport:
    def test_request_returns_httplib2_shaped_response(self) -> None:
        session = _StubSession(
            _StubResponse(200, b'{"items": []}', "OK", {"Content-Encoding": "gzip"})
        )
        http = RequestsTransport(session=session)
        resp, content = http.request(
            "https://compute.googleapis.com/compute/v1/projects/p/instances",
            method="GET",
            headers={"Accept": "application/json"},
        )
        assert content == b'{"items": []}'
        assert resp.status == 200
        assert resp.reason == "OK"
        # header lookups are lowercased, as googleapiclient expects
        assert resp["content-encoding"] == "gzip"
        assert session.calls[0]["timeout"] == DEFAULT_TIMEOUT

    def test_timeout_becomes_a_transport_error(self) -> None:
        import requests

        session = _StubSession(exc=requests.exceptions.Timeout("read timed out"))
        http = RequestsTransport(session=session, timeout=3)
        with pytest.raises(TransportError, match="timeout after 3s"):
            http.request("https://apikeys.googleapis.com/v2/projects/p/locations/global/keys")

    def test_connection_errors_become_transport_errors(self) -> None:
        import requests

        session = _StubSession(exc=requests.exceptions.ConnectionError("dns failure"))
        http = RequestsTransport(session=session)
        with pytest.raises(TransportError, match="transport error"):
            http.request("https://iam.googleapis.com/v1/projects/p/serviceAccounts")

    def test_error_message_does_not_leak_the_full_url_query(self) -> None:
        import requests

        session = _StubSession(exc=requests.exceptions.Timeout("slow"))
        http = RequestsTransport(session=session, timeout=1)
        with pytest.raises(TransportError) as excinfo:
            http.request("https://example.googleapis.com/v1/thing?key=SECRET")
        assert "SECRET" not in str(excinfo.value)
        assert "example.googleapis.com" in str(excinfo.value)

    def test_per_call_timeout_overrides_the_default(self) -> None:
        session = _StubSession()
        http = RequestsTransport(session=session, timeout=30)
        http.request("https://x.googleapis.com/", timeout=9)
        assert session.calls[0]["timeout"] == 9

    def test_zero_timeout_passes_none_to_requests(self) -> None:
        session = _StubSession()
        RequestsTransport(session=session, timeout=0).request("https://x.googleapis.com/")
        assert session.calls[0]["timeout"] is None

    def test_redirections_flag_is_mapped(self) -> None:
        session = _StubSession()
        http = RequestsTransport(session=session)
        http.request("https://x.googleapis.com/", redirections=0)
        assert session.calls[0]["allow_redirects"] is False

    def test_close_closes_the_session(self) -> None:
        session = _StubSession()
        RequestsTransport(session=session).close()
        assert session.closed is True

    def test_headers_are_stringified(self) -> None:
        session = _StubSession()
        RequestsTransport(session=session).request(
            "https://x.googleapis.com/", headers={"Content-Length": 0}
        )
        assert session.calls[0]["headers"] == {"Content-Length": "0"}


# ─────────────────────────────────────────────────────────────────────────────
# Response
# ─────────────────────────────────────────────────────────────────────────────


class TestResponse:
    def test_lowercases_headers_and_exposes_status(self) -> None:
        resp = Response(403, reason="Forbidden", headers={"Content-Type": "application/json"})
        assert resp.status == 403
        assert resp.reason == "Forbidden"
        assert resp["content-type"] == "application/json"

    def test_reason_defaults_to_empty_string(self) -> None:
        assert Response(200).reason == ""


# ─────────────────────────────────────────────────────────────────────────────
# BaseCollector.build_client — a client that cannot be built is a coverage gap
# ─────────────────────────────────────────────────────────────────────────────


class _StubCollector(BaseCollector):
    name = "stub"

    def collect(self, inventory, project_ids, organization_id=None) -> None:  # noqa: D102
        raise NotImplementedError


class TestBuildClientCoverageGap:
    def test_returns_a_client_on_success(self) -> None:
        auth = MagicMock()
        collector = _StubCollector(auth)
        with patch("gcp_abuse_scanner.utils.transport.build_service") as mock_build:
            client = collector.build_client(ResourceInventory(), "compute", "v1")
        assert client is mock_build.return_value
        _, kwargs = mock_build.call_args
        assert kwargs["credentials"] is auth.get_credentials.return_value

    def test_records_a_collector_error_when_building_fails(self) -> None:
        inventory = ResourceInventory()
        collector = _StubCollector(MagicMock())
        with patch(
            "gcp_abuse_scanner.utils.transport.build_service",
            side_effect=RuntimeError("no discovery document"),
        ):
            client = collector.build_client(inventory, "container", "v1")

        assert client is None
        assert len(inventory.collector_errors) == 1
        entry = inventory.collector_errors[0]
        assert entry["collector"] == "stub"
        assert "container/v1 client unavailable" in entry["error"]
        assert "no discovery document" in entry["error"]
        # No project context for a client-level failure — the key is simply absent.
        assert "project_id" not in entry

    def test_transport_settings_are_passed_through(self) -> None:
        collector = _StubCollector(MagicMock(), timeout=4, transport="httplib2")
        with patch("gcp_abuse_scanner.utils.transport.build_service") as mock_build:
            collector.build_client(ResourceInventory(), "run", "v2")
        _, kwargs = mock_build.call_args
        assert kwargs["timeout"] == 4
        assert kwargs["transport"] == "httplib2"


# ─────────────────────────────────────────────────────────────────────────────
# CollectorEngine plumbing
# ─────────────────────────────────────────────────────────────────────────────


class TestEngineWiring:
    def test_engine_injects_transport_settings_into_collectors(self) -> None:
        from gcp_abuse_scanner.collectors.engine import CollectorEngine
        from gcp_abuse_scanner.collectors.quota import QuotaCollector

        engine = CollectorEngine(MagicMock(), timeout=11, transport="httplib2")
        collector = engine._new_collector(QuotaCollector)
        assert isinstance(collector, QuotaCollector)
        assert collector._timeout == 11
        assert collector._transport == "httplib2"

    def test_engine_defaults_leave_the_transport_unset(self) -> None:
        from gcp_abuse_scanner.collectors.engine import CollectorEngine
        from gcp_abuse_scanner.collectors.quota import QuotaCollector

        collector = CollectorEngine(MagicMock())._new_collector(QuotaCollector)
        assert collector._timeout is None
        assert collector._transport is None
