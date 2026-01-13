from collections import ChainMap
from http import HTTPStatus
from unittest.mock import patch

import msal
import pytest
from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY
from django.test import TransactionTestCase, override_settings
from django.urls import reverse


@pytest.mark.django_db
@pytest.mark.usefixtures("token")
@patch.object(msal, "ConfidentialClientApplication")
class TestAzureAuthDecorator(TransactionTestCase):
    def setUp(self):
        s = self.client.session
        s.update({BACKEND_SESSION_KEY: "azure_auth.auth_backends.AzureBackend"})
        s.save()

    def test_invalid_token(self, mocked_msal_app):
        mocked_msal_app.return_value.acquire_token_silent.return_value = None
        resp = self.client.get(reverse("decorator_protected"))
        assert resp.status_code == HTTPStatus.FOUND
        assert resp.url == f"{reverse('azure_auth:login')}?next=/decorator_protected/"  # type: ignore

    @override_settings(
        AZURE_AUTH=ChainMap(
            {"USE_LOGIN_URL": True},
            settings.AZURE_AUTH,
        )
    )
    def test_invalid_token_with_use_login_url(self, mocked_msal_app):
        mocked_msal_app.return_value.acquire_token_silent.return_value = None
        resp = self.client.get(reverse("decorator_protected"))
        assert resp.status_code == HTTPStatus.FOUND
        assert resp.url == f"{settings.LOGIN_URL}?next=/decorator_protected/"  # type: ignore

    def test_valid_token_unauthenticated_user(self, mocked_msal_app):
        # Not sure how this situation could arise but test anyway...

        mocked_msal_app.return_value.acquire_token_silent.return_value = self.token  # type: ignore
        resp = self.client.get(reverse("decorator_protected"))
        assert resp.status_code == HTTPStatus.FOUND
        assert resp.url == f"{reverse('azure_auth:login')}?next=/decorator_protected/"  # type: ignore

    def test_valid_token_authenticated_user(self, mocked_msal_app):
        mocked_msal_app.return_value.acquire_token_silent.return_value = self.token  # type: ignore
        self.client.force_login(self.user)  # type: ignore

        resp = self.client.get(reverse("decorator_protected"))
        assert resp.status_code == HTTPStatus.OK
