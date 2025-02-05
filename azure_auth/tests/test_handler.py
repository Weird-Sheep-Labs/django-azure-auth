from collections import ChainMap

from django.conf import settings
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse_lazy

from azure_auth.handlers import AuthHandler


class TestAzureAuthHandler(TestCase):
    def setUp(self):
        self.request_factory = RequestFactory()
        self.session_midleware = SessionMiddleware(lambda x: "")

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
        self.session_midleware.process_request(req)
        return AuthHandler(req)
