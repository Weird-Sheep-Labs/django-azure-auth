from django.conf import settings
from django.http import HttpRequest
from django.shortcuts import redirect
from django.urls import reverse

from .handlers import AuthHandler


class AzureMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        public_views = ["azure_auth:login", "azure_auth:logout", "azure_auth:callback"]
        public_views.extend(settings.AZURE_AUTH.get("PUBLIC_URLS", []))
        public_urls = [reverse(view_name) for view_name in public_views]
        public_paths = settings.AZURE_AUTH.get(
            "PUBLIC_PATHS", []
        )  # added to resolve paths

        if request.path_info in public_urls:
            return self.get_response(request)

        # Added to resolve paths that can't be reversed
        for path in public_paths:
            if request.path_info.startswith(path):
                return self.get_response(request)

        if AuthHandler(request).user_is_authenticated:
            return self.get_response(request)

        # Save the intended path on the session to be redirected there upon login
        request.session["next"] = request.path
        return redirect("azure_auth:login")
