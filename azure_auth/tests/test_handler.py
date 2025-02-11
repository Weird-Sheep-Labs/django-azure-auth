from collections import ChainMap

import pytest
from django.conf import settings
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse_lazy

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
