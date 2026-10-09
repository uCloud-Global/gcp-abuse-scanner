"""Unit tests for auth layer — AuthManager and ScopeResolver (all offline)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from gcp_abuse_scanner.auth.manager import AuthError, AuthManager

# ─────────────────────────────────────────────────────────────────────────────
# AuthManager — identity property
# ─────────────────────────────────────────────────────────────────────────────


class TestAuthManagerIdentity:
    def test_identity_impersonation(self):
        auth = AuthManager(impersonate_service_account="sa@proj.iam.gserviceaccount.com")
        assert auth.identity == "impersonated:sa@proj.iam.gserviceaccount.com"

    def test_identity_key_file(self):
        auth = AuthManager(service_account_key="/path/to/key.json")
        assert auth.identity == "key_file:/path/to/key.json"

    def test_identity_adc(self):
        auth = AuthManager()
        assert auth.identity == "adc"

    def test_identity_impersonation_takes_precedence_over_key(self):
        auth = AuthManager(
            service_account_key="/path/to/key.json",
            impersonate_service_account="sa@proj.iam.gserviceaccount.com",
        )
        assert auth.identity.startswith("impersonated:")


# ─────────────────────────────────────────────────────────────────────────────
# AuthManager — key file validation
# ─────────────────────────────────────────────────────────────────────────────


class TestAuthManagerKeyFile:
    def test_missing_key_file_raises_auth_error(self):
        auth = AuthManager(service_account_key="/nonexistent/path/key.json")
        with pytest.raises(AuthError, match="not found"):
            auth.get_credentials()

    def test_existing_key_file_calls_from_service_account_file(self, tmp_path):
        # Write a minimal fake SA key JSON
        key_data = {
            "type": "service_account",
            "project_id": "test-proj",
            "private_key_id": "key-id",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
            "client_email": "sa@test-proj.iam.gserviceaccount.com",
            "client_id": "123456",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
        key_file = tmp_path / "sa-key.json"
        key_file.write_text(json.dumps(key_data))

        auth = AuthManager(service_account_key=str(key_file))

        mock_creds = MagicMock()
        with patch(
            "google.oauth2.service_account.Credentials.from_service_account_file",
            return_value=mock_creds,
        ) as mock_load:
            creds = auth.get_credentials()

        mock_load.assert_called_once()
        assert creds is mock_creds

    def test_credentials_cached_after_first_call(self, tmp_path):
        key_file = tmp_path / "sa-key.json"
        key_file.write_text(json.dumps({"type": "service_account"}))

        auth = AuthManager(service_account_key=str(key_file))
        mock_creds = MagicMock()

        with patch(
            "google.oauth2.service_account.Credentials.from_service_account_file",
            return_value=mock_creds,
        ) as mock_load:
            creds1 = auth.get_credentials()
            creds2 = auth.get_credentials()

        # Should only call the loader once
        assert mock_load.call_count == 1
        assert creds1 is creds2


# ─────────────────────────────────────────────────────────────────────────────
# AuthManager — impersonation
# ─────────────────────────────────────────────────────────────────────────────


class TestAuthManagerImpersonation:
    def test_impersonation_calls_google_auth_default(self):
        auth = AuthManager(impersonate_service_account="sa@proj.iam.gserviceaccount.com")

        mock_source_creds = MagicMock()
        mock_impersonated = MagicMock()

        with (
            patch("google.auth.default", return_value=(mock_source_creds, "proj")) as mock_default,
            patch(
                "google.auth.impersonated_credentials.Credentials",
                return_value=mock_impersonated,
            ) as mock_imp,
        ):
            creds = auth.get_credentials()

        mock_default.assert_called_once()
        mock_imp.assert_called_once()
        assert creds is mock_impersonated

    def test_impersonation_passes_target_principal(self):
        sa_email = "scanner@my-proj.iam.gserviceaccount.com"
        auth = AuthManager(impersonate_service_account=sa_email)

        mock_source = MagicMock()
        mock_imp_creds = MagicMock()

        with (
            patch("google.auth.default", return_value=(mock_source, "proj")),
            patch(
                "google.auth.impersonated_credentials.Credentials",
                return_value=mock_imp_creds,
            ) as mock_cls,
        ):
            auth.get_credentials()

        call_kwargs = mock_cls.call_args.kwargs
        assert call_kwargs.get("target_principal") == sa_email


# ─────────────────────────────────────────────────────────────────────────────
# AuthManager — ADC
# ─────────────────────────────────────────────────────────────────────────────


class TestAuthManagerADC:
    def test_adc_calls_google_auth_default(self):
        auth = AuthManager()
        mock_creds = MagicMock()

        with patch("google.auth.default", return_value=(mock_creds, "proj")) as mock_default:
            creds = auth.get_credentials()

        mock_default.assert_called_once()
        assert creds is mock_creds


# ─────────────────────────────────────────────────────────────────────────────
# ScopeResolver — project list mode (no GCP calls)
# ─────────────────────────────────────────────────────────────────────────────


class TestScopeResolverProjectList:
    def _make_resolver(self):
        from gcp_abuse_scanner.auth.scope import ScopeResolver

        mock_auth = MagicMock()
        return ScopeResolver(auth_manager=mock_auth)

    def test_project_list_returned_sorted(self):
        resolver = self._make_resolver()
        result = resolver.resolve_projects(project_ids=["proj-c", "proj-a", "proj-b"])
        assert result == ["proj-a", "proj-b", "proj-c"]

    def test_project_list_deduplicated(self):
        resolver = self._make_resolver()
        result = resolver.resolve_projects(project_ids=["proj-1", "proj-1", "proj-2"])
        assert result == ["proj-1", "proj-2"]

    def test_exclude_projects_removed(self):
        resolver = self._make_resolver()
        result = resolver.resolve_projects(
            project_ids=["proj-1", "proj-2", "proj-3"],
            exclude_project_ids=["proj-2"],
        )
        assert "proj-2" not in result
        assert "proj-1" in result
        assert "proj-3" in result

    def test_exclude_all_returns_empty(self):
        resolver = self._make_resolver()
        result = resolver.resolve_projects(
            project_ids=["proj-1"],
            exclude_project_ids=["proj-1"],
        )
        assert result == []

    def test_no_org_no_projects_raises(self):
        resolver = self._make_resolver()
        with pytest.raises((ValueError, Exception)):
            resolver.resolve_projects()

    def test_empty_project_list_raises(self):
        """Empty list is falsy — ScopeResolver treats it as 'no scope provided'."""
        resolver = self._make_resolver()
        with pytest.raises((ValueError, Exception)):
            resolver.resolve_projects(project_ids=[])

    def test_exclude_nonexistent_project_no_error(self):
        resolver = self._make_resolver()
        result = resolver.resolve_projects(
            project_ids=["proj-1"],
            exclude_project_ids=["proj-nonexistent"],
        )
        assert result == ["proj-1"]


# ─────────────────────────────────────────────────────────────────────────────
# ScopeResolver — org mode (mocked GCP call)
# ─────────────────────────────────────────────────────────────────────────────


class TestScopeResolverOrgMode:
    def _make_resolver(self):
        from gcp_abuse_scanner.auth.scope import ScopeResolver

        mock_auth = MagicMock()
        mock_auth.get_credentials.return_value = MagicMock()
        return ScopeResolver(auth_manager=mock_auth)

    def _make_resource(self, project_id: str, state: str = "ACTIVE"):
        r = MagicMock()
        r.name = f"//cloudresourcemanager.googleapis.com/projects/{project_id}"
        r.state = state
        return r

    def test_org_mode_returns_active_projects(self):
        resolver = self._make_resolver()
        mock_resources = [
            self._make_resource("proj-1", "ACTIVE"),
            self._make_resource("proj-2", "ACTIVE"),
            self._make_resource("proj-deleted", "DELETE_REQUESTED"),
        ]

        with patch("google.cloud.asset_v1.AssetServiceClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.search_all_resources.return_value = mock_resources
            mock_client_cls.return_value = mock_client

            result = resolver.resolve_projects(organization_id="123456789")

        assert "proj-1" in result
        assert "proj-2" in result
        assert "proj-deleted" not in result

    def test_org_mode_excludes_specified_projects(self):
        resolver = self._make_resolver()
        mock_resources = [
            self._make_resource("proj-1", "ACTIVE"),
            self._make_resource("proj-sandbox", "ACTIVE"),
        ]

        with patch("google.cloud.asset_v1.AssetServiceClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.search_all_resources.return_value = mock_resources
            mock_client_cls.return_value = mock_client

            result = resolver.resolve_projects(
                organization_id="123456789",
                exclude_project_ids=["proj-sandbox"],
            )

        assert "proj-sandbox" not in result
        assert "proj-1" in result

    def test_org_mode_api_failure_raises(self):
        resolver = self._make_resolver()

        with patch("google.cloud.asset_v1.AssetServiceClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.search_all_resources.side_effect = Exception("Permission denied")
            mock_client_cls.return_value = mock_client

            with pytest.raises(Exception, match="Permission denied"):
                resolver.resolve_projects(organization_id="123456789")


# ─────────────────────────────────────────────────────────────────────────────
# AuthManager — non service-account credential files
# ─────────────────────────────────────────────────────────────────────────────

_AUTHORIZED_USER = {
    "type": "authorized_user",
    "client_id": "x.apps.googleusercontent.com",
    "client_secret": "secret",
    "refresh_token": "token",
}
_EXTERNAL_ACCOUNT = {
    "type": "external_account",
    "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/gh",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "token_url": "https://sts.googleapis.com/v1/token",
    "credential_source": {"file": "/tmp/oidc-token"},
}


class TestAuthManagerNonKeyCredentialFiles:
    @pytest.mark.parametrize("payload", [_AUTHORIZED_USER, _EXTERNAL_ACCOUNT])
    def test_env_credential_file_falls_back_to_adc(self, tmp_path, monkeypatch, payload):
        cred_file = tmp_path / "creds.json"
        cred_file.write_text(json.dumps(payload))
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(cred_file))

        auth = AuthManager(service_account_key=str(cred_file))
        mock_creds = MagicMock()
        with (
            patch("google.auth.default", return_value=(mock_creds, None)) as mock_default,
            patch(
                "google.oauth2.service_account.Credentials.from_service_account_file"
            ) as mock_key_loader,
        ):
            creds = auth.get_credentials()

        assert creds is mock_creds
        mock_default.assert_called_once()
        mock_key_loader.assert_not_called()

    def test_env_credential_file_identity_is_adc(self, tmp_path, monkeypatch):
        cred_file = tmp_path / "creds.json"
        cred_file.write_text(json.dumps(_AUTHORIZED_USER))
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(cred_file))

        assert AuthManager(service_account_key=str(cred_file)).identity == "adc"

    def test_explicit_non_key_file_raises_auth_error(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
        cred_file = tmp_path / "creds.json"
        cred_file.write_text(json.dumps(_AUTHORIZED_USER))

        auth = AuthManager(service_account_key=str(cred_file))
        with pytest.raises(AuthError, match="not a service account key"):
            auth.get_credentials()

    def test_unparseable_file_raises_auth_error(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
        cred_file = tmp_path / "creds.json"
        cred_file.write_text("not json")

        with pytest.raises(AuthError, match="type=None"):
            AuthManager(service_account_key=str(cred_file)).get_credentials()

    def test_impersonation_ignores_env_credential_file(self, tmp_path, monkeypatch):
        cred_file = tmp_path / "creds.json"
        cred_file.write_text(json.dumps(_EXTERNAL_ACCOUNT))
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(cred_file))

        auth = AuthManager(
            service_account_key=str(cred_file),
            impersonate_service_account="sa@proj.iam.gserviceaccount.com",
        )
        with (
            patch("google.auth.default", return_value=(MagicMock(), None)),
            patch("google.auth.impersonated_credentials.Credentials") as mock_imp,
        ):
            auth.get_credentials()

        mock_imp.assert_called_once()
