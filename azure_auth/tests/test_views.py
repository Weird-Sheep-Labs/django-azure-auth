from http import HTTPStatus
from unittest.mock import call, patch

import msal
import pytest
from django.test import TestCase
from django.urls import reverse


@pytest.mark.usefixtures("auth_flow")
@patch.object(msal, "ConfidentialClientApplication")
class TestLoginView(TestCase):

    # TODO: What about if user is already logs in and hits this view
    # TODO: Any other breaking flows?
    def test_login(self, mocked_msal_app):
        mocked_msal_app.return_value.initiate_auth_code_flow.return_value = (
            self.auth_flow
        )
        resp = self.client.get(reverse("login"))
        assert resp.status_code == HTTPStatus.FOUND
        assert resp.url == "https://aad-auth-uri.com"
        assert self.client.session._session == {
            "auth_flow": {
                "state": "dummy_state",
                "redirect_uri": "http://localhost:8000/azure_auth/callback",
                "scope": ["profile", "offline_access", "User.Read", "openid"],
                "auth_uri": "https://aad-auth-uri.com",
            }
        }

        # MSAL calls
        mocked_msal_app.assert_called_once_with(
            client_id="dummy_client_id",
            client_credential="dummy_client_secret",
            authority="https://login.microsoftonline.com/dummy_tenant_id",
            # Don't care about the `token_cache` object so just pipe it in
            token_cache=mocked_msal_app.call_args.kwargs["token_cache"],
        )

        mocked_msal_app.return_value.initiate_auth_code_flow.assert_called_once_with(
            scopes=["User.Read"],
            redirect_uri="http://localhost:8000/azure_auth/callback",
        )


@pytest.mark.usefixtures("token")
@pytest.mark.usefixtures("auth_flow")
@patch("azure_auth.handlers.requests")
@patch.object(msal, "ConfidentialClientApplication")
class TestCallbackView(TestCase):
    def setUp(self):
        super().setUp()
        # Store in variable first
        # https://docs.djangoproject.com/en/4.0/topics/testing/tools/
        session = self.client.session
        session["auth_flow"] = self.auth_flow
        session.save()

    def mocked_response(self, code, json):
        class MockResponse:
            def __init__(self, status_code, data):
                self.status_code = status_code
                self.data = data
                self.ok = True if self.status_code == 200 else False

            def json(self):
                return self.data

        return MockResponse(code, json)

    @staticmethod
    def get_graph_response(user):
        return {
            "givenName": user.first_name,
            "mail": user.email,
            "surname": user.last_name,
        }

    def test_callback_user_exists(self, mocked_msal_app, mocked_requests):
        mocked_msal_app.return_value.acquire_token_by_auth_code_flow.return_value = (
            self.token
        )

        # Graph API response
        expected_response_json = self.get_graph_response(self.user)
        mocked_requests.get.side_effect = [
            self.mocked_response(HTTPStatus.OK, expected_response_json)
        ]
        resp = self.client.get(reverse("callback"))
        assert resp.status_code == HTTPStatus.FOUND
        assert resp.url == "/"

        # MSAL calls
        mocked_msal_app.assert_called_once_with(
            client_id="dummy_client_id",
            client_credential="dummy_client_secret",
            authority="https://login.microsoftonline.com/dummy_tenant_id",
            # Don't care about the `token_cache` object so just pipe it in
            token_cache=mocked_msal_app.call_args.kwargs["token_cache"],
        )
        m_acf = mocked_msal_app.return_value.acquire_token_by_auth_code_flow
        m_acf.assert_called_once_with(
            auth_code_flow=self.auth_flow,
            # The request for this view comes from the auth server so just pipe
            # `auth_response` in
            auth_response=m_acf.call_args.kwargs["auth_response"],
        )

        # Graph API calls
        mocked_requests.get.assert_called_once_with(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": "Bearer dummy_access_token"},
        )


@patch.object(msal, "ConfidentialClientApplication")
class TestLogoutView(TestCase):
    def setUp(self):
        super().setUp()

    def test_logout(self, mocked_msal_app):
        pass
