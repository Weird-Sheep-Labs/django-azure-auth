from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse

from .handlers import AuthHandler


class AzureMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        public_views = ["azure_auth:login", "azure_auth:logout", "azure_auth:callback"]
        public_views.extend(settings.AZURE_AUTH.get("PUBLIC_URLS", []))
        public_urls = [reverse(view_name) for view_name in public_views]

        if request.path_info in public_urls:
            return self.get_response(request)

        if AuthHandler(request).get_token_from_cache():
            # If the user is authenticated
            if request.user.is_authenticated:
                return self.get_response(request)
        return redirect("azure_auth:login")
