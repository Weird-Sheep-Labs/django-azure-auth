from urllib.parse import unquote

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.http import HttpRequest, HttpResponseForbidden, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme

from azure_auth.utils import EntraStateSerializer

from .handlers import AuthHandler

serializer = EntraStateSerializer()


def azure_auth_login(request: HttpRequest):
    return HttpResponseRedirect(
        AuthHandler(request).get_auth_uri(
            state=serializer.serialize(next=request.GET.get("next"))
        )
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
        next = serializer.deserialize(unquote(request.GET.get("state", ""))).get(
            "next", ""
        )
        if url_has_allowed_host_and_scheme(next, allowed_hosts=None):
            return HttpResponseRedirect(next)
        return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)
    return HttpResponseForbidden("Invalid email for this app.")
