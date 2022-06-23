from http import HTTPStatus
from unittest.mock import patch

import msal
import pytest
from django.conf import settings
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
        assert resp.url == self.auth_flow["auth_uri"]
        assert self.client.session._session == {"auth_flow": self.auth_flow}

        # MSAL calls
        mocked_msal_app.assert_called_once_with(
            client_id=settings.AZURE_AUTH["CLIENT_ID"],
            client_credential=settings.AZURE_AUTH["CLIENT_SECRET"],
            authority=settings.AZURE_AUTH["AUTHORITY"],
            # Don't care about the `token_cache` object so just pipe it in
            token_cache=mocked_msal_app.call_args.kwargs["token_cache"],
        )

        mocked_msal_app.return_value.initiate_auth_code_flow.assert_called_once_with(
            scopes=settings.AZURE_AUTH["SCOPES"],
            redirect_uri=settings.AZURE_AUTH["REDIRECT_URI"],
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
        assert resp.url == settings.LOGIN_REDIRECT_URL

        # MSAL calls
        mocked_msal_app.assert_called_once_with(
            client_id=settings.AZURE_AUTH["CLIENT_ID"],
            client_credential=settings.AZURE_AUTH["CLIENT_SECRET"],
            authority=settings.AZURE_AUTH["AUTHORITY"],
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
            headers={"Authorization": f"Bearer {self.token['access_token']}"},
        )


@patch.object(msal, "ConfidentialClientApplication")
class TestLogoutView(TestCase):
    def setUp(self):
        super().setUp()

    def test_logout(self, mocked_msal_app):
        pass
