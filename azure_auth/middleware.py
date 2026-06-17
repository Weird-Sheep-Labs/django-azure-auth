from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY
from django.http import HttpRequest
from django.shortcuts import redirect
from django.urls import reverse

from .handlers import AuthHandler


class AzureMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        public_views = ["azure_auth:login", "azure_auth:logout", "azure_auth:callback"]
        public_views.extend(settings.AZURE_AUTH.get("PUBLIC_URLS", []))
        self.public_urls = [reverse(view_name) for view_name in public_views]
        self.public_paths = settings.AZURE_AUTH.get(
            "PUBLIC_PATHS", []
        )  # added to resolve paths

    def __call__(self, request: HttpRequest):
        active_auth_backend = request.session.get(BACKEND_SESSION_KEY, "")

        if request.path_info in self.public_urls:
            return self.get_response(request)

        # Added to resolve paths that can't be reversed
        for path in self.public_paths:
            if request.path_info.startswith(path):
                return self.get_response(request)

        if AuthHandler(request).user_is_authenticated:
            return self.get_response(request)
        elif active_auth_backend != "azure_auth.auth_backends.AzureBackend":
            # User is handled by another backend
            return self.get_response(request)

        if settings.AZURE_AUTH.get("USE_LOGIN_URL", False):
            return redirect(f"{settings.LOGIN_URL}?next={urlparse(request.path).path}")

        return redirect(
            f"{reverse('azure_auth:login')}?next={urlparse(request.path).path}"
        )
