from http import HTTPStatus
from unittest.mock import patch

import msal
import pytest
from django.test import TransactionTestCase
from django.urls import reverse


@pytest.mark.django_db
@pytest.mark.usefixtures("token")
@patch.object(msal, "ConfidentialClientApplication")
class TestAzureAuthMiddleware(TransactionTestCase):
    def test_invalid_token(self, mocked_msal_app):
        mocked_msal_app.return_value.acquire_token_silent.return_value = None
        resp = self.client.get(reverse("middleware_protected"))
        assert resp.status_code == HTTPStatus.FOUND
        assert resp.url == reverse("azure_auth:login")  # type: ignore

    def test_valid_token_unauthenticated_user(self, mocked_msal_app):
        # Not sure how this situation could arise but test anyway...

        mocked_msal_app.return_value.acquire_token_silent.return_value = self.token  # type: ignore
        resp = self.client.get(reverse("middleware_protected"))
        assert resp.status_code == HTTPStatus.FOUND
        assert resp.url == reverse("azure_auth:login")  # type: ignore

    def test_valid_token_authenticated_user(self, mocked_msal_app):
        mocked_msal_app.return_value.acquire_token_silent.return_value = self.token  # type: ignore
        self.client.force_login(self.user)  # type: ignore

        resp = self.client.get(reverse("middleware_protected"))
        assert resp.status_code == HTTPStatus.OK

    def test_public_view(self, mocked_msal_app):
        mocked_msal_app.return_value.acquire_token_silent.return_value = None
        resp = self.client.get(reverse("public"))
        assert resp.status_code == HTTPStatus.OK

    def test_public_external_view(self, mocked_msal_app):
        mocked_msal_app.return_value.acquire_token_silent.return_value = None
        resp = self.client.get(reverse("public_external"))
        assert resp.status_code == HTTPStatus.OK
