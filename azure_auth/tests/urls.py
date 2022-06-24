from django.http import HttpResponse
from django.urls import include, path

from azure_auth.decorators import azure_auth_required


def test_view(request):
    return HttpResponse("not a real view")


@azure_auth_required
def protected_view(request):
    return HttpResponse("A view protected by the decorator")


urlpatterns = [
    path("", test_view),
    path("protected/", protected_view, name="protected"),
    path("named/", test_view, name="named-url"),
    path(
        "azure_auth/",
        include("azure_auth.urls"),
    ),
]
