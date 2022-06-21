import functools

from django.shortcuts import redirect


def azure_auth_required(func):
    @functools.wraps(func)
    def _wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("/azure_auth/login")
        return func(request, *args, **kwargs)

    return _wrapper
