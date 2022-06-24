from django.urls import path

from azure_auth.views import azure_auth_callback, azure_auth_login, azure_auth_logout

app_name = "azure_auth"
urlpatterns = [
    path("login", azure_auth_login, name="login"),
    path("logout", azure_auth_logout, name="logout"),
    path("callback", azure_auth_callback, name="callback"),
]
