from collections import ChainMap
from unittest.mock import patch

import pytest
from django.conf import settings
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import RequestFactory
from django.test import TestCase
from django.test import override_settings
from django.urls import reverse_lazy

from azure_auth.exceptions import DjangoAzureAuthException
from azure_auth.handlers import AuthHandler


@pytest.mark.django_db
@pytest.mark.usefixtures("token")
class TestAzureAuthHandler(TestCase):
    def setUp(self):
        self.request_factory = RequestFactory()
        self.session_middleware = SessionMiddleware(lambda x: HttpResponse())

    @override_settings(
        AZURE_AUTH=ChainMap(
            {"REDIRECT_URI": "http://testserver/azure_auth/callback_absolut"},
            settings.AZURE_AUTH,
        )
    )
    def test_callback_uri_absolut(self):
        handler = self._build_auth_handler()
        redirect_uri = handler._get_redirect_uri()
        self.assertEqual(redirect_uri, "http://testserver/azure_auth/callback_absolut")

    @override_settings(
        AZURE_AUTH=ChainMap(
            {"REDIRECT_URI": "/azure_auth/callback_relative"}, settings.AZURE_AUTH
        )
    )
    def test_callback_uri_relative(self):
        handler = self._build_auth_handler()
        redirect_uri = handler._get_redirect_uri()
        self.assertEqual(redirect_uri, "http://testserver/azure_auth/callback_relative")

    @override_settings(
        AZURE_AUTH=ChainMap(
            {"REDIRECT_URI": reverse_lazy("decorator_protected")}, settings.AZURE_AUTH
        )
    )
    def test_callback_uri_reverse_lazy(self):
        handler = self._build_auth_handler()
        redirect_uri = handler._get_redirect_uri()
        self.assertEqual(redirect_uri, "http://testserver/decorator_protected/")

    def _build_auth_handler(self) -> AuthHandler:
        req = self.request_factory.get("/")
        self.session_middleware.process_request(req)
        return AuthHandler(req)

    def test_group_mapping(self):
        handler = self._build_auth_handler()
        handler.sync_groups(self.user, self.token)
        self.assertEqual(self.user.groups.count(), 1)

    @override_settings(
        AZURE_AUTH=ChainMap(
            {
                "ROLES": {
                    # Just some random GUID, that is not in the token
                    "a1ad6d75-11c5-442b-9b32-17bdebe82427": "GroupName1",
                }
            },
            settings.AZURE_AUTH,
        )
    )
    def test_no_mapping(self):
        handler = self._build_auth_handler()
        handler.sync_groups(self.user, self.token)
        self.assertEqual(self.user.groups.count(), 0)

    @override_settings(
        AZURE_AUTH=ChainMap(
            {
                "ROLES": {
                    "95170e67-2bbf-4e3e-a4d7-e7e5829fe7a7": ["GroupName1"],
                }
            },
            settings.AZURE_AUTH,
        )
    )
    def test_single_group_list_mapping(self):
        handler = self._build_auth_handler()
        handler.sync_groups(self.user, self.token)
        self.assertEqual(self.user.groups.count(), 1)

    @override_settings(
        AZURE_AUTH=ChainMap(
            {
                "ROLES": {
                    "95170e67-2bbf-4e3e-a4d7-e7e5829fe7a7": [
                        "GroupName1",
                        "GroupName2",
                    ],
                }
            },
            settings.AZURE_AUTH,
        )
    )
    def test_multi_group_list_mapping(self):
        handler = self._build_auth_handler()
        handler.sync_groups(self.user, self.token)
        self.assertEqual(self.user.groups.count(), 2)

    @override_settings(
        AZURE_AUTH=ChainMap(
            {
                "ROLES": {
                    "95170e67-2bbf-4e3e-a4d7-e7e5829fe7a7": [
                        "GroupName1",
                        "",
                    ],
                }
            },
            settings.AZURE_AUTH,
        )
    )
    def test_multi_group_list_mapping_with_empty(self):
        handler = self._build_auth_handler()
        handler.sync_groups(self.user, self.token)
        self.assertEqual(self.user.groups.count(), 1)

    @override_settings(
        AZURE_AUTH=ChainMap(
            {
                "ROLES": {
                    "95170e67-2bbf-4e3e-a4d7-e7e5829fe7a7": [
                        "GroupName1",
                        None,
                    ],
                }
            },
            settings.AZURE_AUTH,
        )
    )
    def test_multi_group_list_mapping_with_none(self):
        handler = self._build_auth_handler()
        handler.sync_groups(self.user, self.token)
        self.assertEqual(self.user.groups.count(), 1)

    @override_settings(
        AZURE_AUTH=ChainMap(
            {
                "ROLES": {
                    "95170e67-2bbf-4e3e-a4d7-e7e5829fe7a7": [],
                }
            },
            settings.AZURE_AUTH,
        )
    )
    def test_empty_group_list_mapping(self):
        handler = self._build_auth_handler()
        handler.sync_groups(self.user, self.token)
        self.assertEqual(self.user.groups.count(), 0)

    @override_settings(
        AZURE_AUTH=ChainMap(
            {
                "ROLES": {
                    "95170e67-2bbf-4e3e-a4d7-e7e5829fe7a7": [
                        "GroupName1",
                        "GroupName2",
                        "GroupName3",
                    ],
                    "cfa8556d-dd93-420c-abd2-477ba336d2d6": "GroupName1",
                    "e236600b-7062-4bff-8ccf-12d8fbd80e5f": "GroupName1",
                }
            },
            settings.AZURE_AUTH,
        )
    )
    def test_multiple_roles_to_one_group(self):
        handler = self._build_auth_handler()
        handler.sync_groups(self.user, self.token)
        self.assertEqual(self.user.groups.count(), 3)

    @override_settings(
        AZURE_AUTH=ChainMap(
            {
                "CLIENT_CREDENTIAL_TYPE": "certificate",
                "PRIVATE_KEY": (
                    "-----BEGIN PRIVATE KEY-----\n"
                    "FAKE/KEY+BAQEFAASCBKcwggSjAgEAAoIBAQDL7+6Z1g5r8V3y\n"
                    "-----END PRIVATE KEY-----"
                ),
                "PUBLIC_CERTIFICATE": (
                    "-----BEGIN CERTIFICATE-----\n"
                    "FAKE/CERT+Z1g5r8V3yMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n"
                    "-----END CERTIFICATE-----"
                ),
            },
            settings.AZURE_AUTH,
        )
    )
    @patch("azure_auth.handlers.msal.ConfidentialClientApplication")
    def test_msal_app_from_certificate(self, mocked_client):
        handler = self._build_auth_handler()
        msal_app = handler.msal_app

        mocked_client.assert_called_once_with(
            client_id=settings.AZURE_AUTH["CLIENT_ID"],
            client_credential={
                "private_key": settings.AZURE_AUTH["PRIVATE_KEY"],
                "public_certificate": settings.AZURE_AUTH["PUBLIC_CERTIFICATE"],
            },
            authority=settings.AZURE_AUTH["AUTHORITY"],
            token_cache=handler.cache,
        )
        self.assertIs(msal_app, mocked_client.return_value)

        # A second access should reuse the same client.
        self.assertIs(handler.msal_app, msal_app)
        mocked_client.assert_called_once()

    @override_settings(
        AZURE_AUTH=ChainMap(
            {
                "CLIENT_SECRET": "My-Fake-Test-Secret",
            },
            settings.AZURE_AUTH,
        )
    )
    @patch("azure_auth.handlers.msal.ConfidentialClientApplication")
    def test_msal_app_from_secret(self, mocked_client):
        handler = self._build_auth_handler()
        msal_app = handler.msal_app

        mocked_client.assert_called_once_with(
            client_id=settings.AZURE_AUTH["CLIENT_ID"],
            client_credential=settings.AZURE_AUTH["CLIENT_SECRET"],
            authority=settings.AZURE_AUTH["AUTHORITY"],
            token_cache=handler.cache,
        )
        self.assertIs(msal_app, mocked_client.return_value)

        # A second access should reuse the same client.
        self.assertIs(handler.msal_app, msal_app)
        mocked_client.assert_called_once()

    @override_settings(
        AZURE_AUTH=ChainMap(
            {"PRIVATE_KEY": "bla bla bla, invalid PEM"},
            settings.AZURE_AUTH,
        )
    )
    def test_private_key_invalid(self):
        handler = self._build_auth_handler()
        with self.assertRaises(DjangoAzureAuthException):
            handler._get_private_key()
