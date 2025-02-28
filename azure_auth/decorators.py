import functools
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, decorators
from django.shortcuts import redirect
from django.urls import reverse

from .handlers import AuthHandler


def _dummy_login_not_required(view_func):
    return view_func


# The login_not_required decorator was added in Django 5.1
# For earlier version we use a dummy decorator
login_not_required = getattr(
    decorators, "login_not_required", _dummy_login_not_required
)


def azure_auth_required(func):
    @functools.wraps(func)
    def _wrapper(request, *args, **kwargs):
        active_auth_backend = request.session.get(BACKEND_SESSION_KEY, "")

        # If the token is valid (or a new valid one can be generated)
        if AuthHandler(request).user_is_authenticated:
            return func(request, *args, **kwargs)
        elif active_auth_backend != "azure_auth.auth_backends.AzureBackend":
            # User is handled by another backend
            return func(request, *args, **kwargs)
        if settings.AZURE_AUTH.get("USE_LOGIN_URL", False):
            return redirect(f"{settings.LOGIN_URL}?next={urlparse(request.path).path}")

        return redirect(
            f"{reverse('azure_auth:login')}?next={urlparse(request.path).path}"
        )

    return _wrapper
