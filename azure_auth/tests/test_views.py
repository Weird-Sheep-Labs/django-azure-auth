from http import HTTPStatus
from unittest.mock import patch

import msal
import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from mixer.backend.django import Mixer

from azure_auth.exceptions import TokenError

UserModel = get_user_model()


@pytest.mark.django_db
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


@pytest.mark.django_db
@pytest.mark.usefixtures("token")
@pytest.mark.usefixtures("auth_flow")
@patch("azure_auth.handlers.requests")
@patch.object(msal, "ConfidentialClientApplication")
class TestCallbackView(TransactionTestCase):
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

    def azure_asserts(self, mocked_msal_app, mocked_requests):
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

    def test_callback_existing_user(self, mocked_msal_app, mocked_requests):
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

        self.azure_asserts(mocked_msal_app, mocked_requests)

    def test_callback_new_user(self, mocked_msal_app, mocked_requests):
        mocked_msal_app.return_value.acquire_token_by_auth_code_flow.return_value = (
            self.token
        )

        # Generate unsaved new user instance
        custom_mixer = Mixer(commit=False)
        new_user = custom_mixer.blend(UserModel)
        assert len(UserModel.objects.all()) == 1

        # Graph API response
        expected_response_json = self.get_graph_response(new_user)
        mocked_requests.get.side_effect = [
            self.mocked_response(HTTPStatus.OK, expected_response_json)
        ]
        resp = self.client.get(reverse("callback"))
        assert resp.status_code == HTTPStatus.FOUND
        assert resp.url == settings.LOGIN_REDIRECT_URL

        self.azure_asserts(mocked_msal_app, mocked_requests)

        # User creation checks
        created_user = UserModel.objects.get(email=new_user.email)
        assert created_user.username == new_user.email
        assert created_user.first_name == new_user.first_name
        assert created_user.last_name == new_user.last_name

    def test_callback_unauthorized(self, mocked_msal_app, mocked_requests):
        mocked_msal_app.return_value.acquire_token_by_auth_code_flow.return_value = (
            self.token
        )

        # Graph API response
        mocked_requests.get.side_effect = [
            self.mocked_response(
                HTTPStatus.UNAUTHORIZED,
                {"error": {"code": "dummy_error", "message": "dummy_message"}},
            )
        ]

        with pytest.raises(TokenError) as exc:
            self.client.get(reverse("callback"))
        assert str(exc.value) == "dummy_error\ndummy_message"

        self.azure_asserts(mocked_msal_app, mocked_requests)


@patch.object(msal, "ConfidentialClientApplication")
class TestLogoutView(TestCase):
    def setUp(self):
        super().setUp()

    def test_logout(self, mocked_msal_app):
        pass
