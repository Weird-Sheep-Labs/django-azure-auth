import datetime
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
        assert resp.url == f"{reverse('azure_auth:login')}?next=/middleware_protected/"  # type: ignore

    def test_valid_token_unauthenticated_user(self, mocked_msal_app):
        # Not sure how this situation could arise but test anyway...

        mocked_msal_app.return_value.acquire_token_silent.return_value = self.token  # type: ignore
        resp = self.client.get(reverse("middleware_protected"))
        assert resp.status_code == HTTPStatus.FOUND
        assert resp.url == f"{reverse('azure_auth:login')}?next=/middleware_protected/"  # type: ignore

    def test_valid_token_authenticated_user(self, mocked_msal_app):
        mocked_msal_app.return_value.acquire_token_silent.return_value = self.token  # type: ignore
        self.client.force_login(self.user)  # type: ignore

        resp = self.client.get(reverse("middleware_protected"))
        assert resp.status_code == HTTPStatus.OK
        assert mocked_msal_app.return_value.acquire_token_silent.call_count == 1

    def test_valid_id_token_claims_authenticated_user(self, mocked_msal_app):
        self.client.force_login(self.user)  # type: ignore

        # Set up valid id token claims in session
        session = self.client.session
        session["id_token_claims"] = {
            "exp": datetime.datetime.now(datetime.timezone.utc).timestamp() + 10
        }
        session.save()

        resp = self.client.get(reverse("middleware_protected"))
        assert resp.status_code == HTTPStatus.OK
        assert mocked_msal_app.return_value.acquire_token_silent.call_count == 0

    def test_expired_id_token_claims_authenticated_user(self, mocked_msal_app):
        # Set up mocked incoming token
        new_token_expiry = (
            datetime.datetime.now(datetime.timezone.utc).timestamp() + 1000
        )
        new_token = self.token  # type: ignore
        new_token["id_token_claims"]["exp"] = new_token_expiry

        mocked_msal_app.return_value.acquire_token_silent.return_value = new_token
        self.client.force_login(self.user)  # type: ignore

        # Set up expired id token claims in session
        session = self.client.session
        session["id_token_claims"] = {
            "exp": datetime.datetime.now(datetime.timezone.utc).timestamp() - 10
        }
        session.save()

        resp = self.client.get(reverse("middleware_protected"))
        assert resp.status_code == HTTPStatus.OK
        assert mocked_msal_app.return_value.acquire_token_silent.call_count == 1
        assert self.client.session["id_token_claims"]["exp"] == new_token_expiry

    def test_public_view(self, mocked_msal_app):
        mocked_msal_app.return_value.acquire_token_silent.return_value = None
        resp = self.client.get(reverse("public"))
        assert resp.status_code == HTTPStatus.OK

    def test_public_external_view(self, mocked_msal_app):
        mocked_msal_app.return_value.acquire_token_silent.return_value = None
        resp = self.client.get(reverse("public_external"))
        assert resp.status_code == HTTPStatus.OK
