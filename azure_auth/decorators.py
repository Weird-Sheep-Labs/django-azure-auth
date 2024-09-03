import functools
from urllib.parse import urlparse

from django.shortcuts import redirect
from django.urls import reverse

from .handlers import AuthHandler


def azure_auth_required(func):
    @functools.wraps(func)
    def _wrapper(request, *args, **kwargs):
        # If the token is valid (or a new valid one can be generated)
        if AuthHandler(request).user_is_authenticated:
            return func(request, *args, **kwargs)
        return redirect(
            f"{reverse('azure_auth:login')}?next={urlparse(request.path).path}"
        )

    return _wrapper
