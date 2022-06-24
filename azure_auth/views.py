from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseForbidden, HttpResponseRedirect

from .handlers import AuthHandler


def azure_auth_login(request):
    return HttpResponseRedirect(AuthHandler(request).get_auth_uri())


def azure_auth_logout(request):
    logout(request)
    return HttpResponseRedirect(AuthHandler.get_logout_uri())


def azure_auth_callback(request):
    token = AuthHandler(request).get_token_from_flow()
    user = authenticate(request, token=token)
    if user:
        login(request, user)
    else:
        return HttpResponseForbidden("Invalid email for this app.")
    return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)
