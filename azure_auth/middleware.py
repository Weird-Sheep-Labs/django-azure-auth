from django.shortcuts import redirect
from django.urls import reverse

from .handlers import AuthHandler


class AzureAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        public_views = ["login", "logout", "callback"]
        public_urls = [reverse(f"azure_auth:{view_name}") for view_name in public_views]

        if request.path_info in public_urls:
            return self.get_response(request)

        if AuthHandler(request).get_token_from_cache():
            # If the user is authenticated
            if request.user.is_authenticated:
                return self.get_response(request)
        return redirect("azure_auth:login")
