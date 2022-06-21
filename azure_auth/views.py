from django.conf import settings
from django.contrib.auth import login, logout
from django.http import HttpResponseForbidden, HttpResponseRedirect

from .client import MSALClient


def azure_auth_login(request):
    flow = MSALClient(request).get_flow()
    return HttpResponseRedirect(flow["auth_uri"])


def azure_auth_logout(request):
    logout(request)
    return HttpResponseRedirect(MSALClient().logout_url)


def azure_auth_callback(request):
    user = MSALClient(request).authenticate()
    if user:
        login(request, user)
    else:
        return HttpResponseForbidden("Invalid email for this app.")
    # TODO: Override this with a default in conf.py
    return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL or "/admin")
