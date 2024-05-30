from urllib.parse import quote

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.http import HttpRequest, HttpResponseForbidden, HttpResponseRedirect

from .handlers import AuthHandler


def azure_auth_login(request: HttpRequest):
    return HttpResponseRedirect(
        AuthHandler(request).get_auth_uri(state=request.GET.get("next"))
    )


def azure_auth_logout(request: HttpRequest):
    # Auth handler has to be initialized before `logout()` to load the claims from the session
    auth_handler = AuthHandler(request)

    logout(request)
    return HttpResponseRedirect(auth_handler.get_logout_uri())


def azure_auth_callback(request: HttpRequest):
    token = AuthHandler(request).get_token_from_flow()
    user = authenticate(request, token=token)
    if user:
        login(request, user)

        # Get `state` query param returned by AAD
        next = quote(request.GET.get("state", ""), safe="/")
    else:
        return HttpResponseForbidden("Invalid email for this app.")
    return HttpResponseRedirect(next or settings.LOGIN_REDIRECT_URL)
