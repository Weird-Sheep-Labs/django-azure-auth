from django.urls import path

from azure_auth.views import (
    azure_auth_callback,
    azure_auth_login,
    azure_auth_logout,
    wam_auth_login,
)
from azure_auth.utils import is_broker_enabled

app_name = "azure_auth"

_login_function = azure_auth_login if not is_broker_enabled() else wam_auth_login
urlpatterns = [
    path("login", _login_function, name="login"),
    path("logout", azure_auth_logout, name="logout"),
    path("callback", azure_auth_callback, name="callback"),
]
