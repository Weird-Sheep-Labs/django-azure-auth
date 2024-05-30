import functools

from django.shortcuts import redirect

from .handlers import AuthHandler


def azure_auth_required(func):
    @functools.wraps(func)
    def _wrapper(request, *args, **kwargs):
        # If the token is valid (or a new valid one can be generated)
        if AuthHandler(request).user_is_authenticated:
            return func(request, *args, **kwargs)

        # Save the intended path on the session to be redirected there upon login
        request.session["next"] = request.path
        return redirect("azure_auth:login")

    return _wrapper
