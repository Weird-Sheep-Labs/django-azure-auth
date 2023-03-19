from django.http import HttpResponse
from django.urls import include, path

from azure_auth.decorators import azure_auth_required


def test_view(request):
    return HttpResponse("not a real view")


def public_view(request):
    return HttpResponse("Public view")


def public_external_view(request):
    return HttpResponse("Public external view")


def middleware_protected_view(request):
    return HttpResponse("A view protected by the middleware")


@azure_auth_required
def decorator_protected_view(request):
    return HttpResponse("A view protected by the decorator")


urlpatterns = [
    path("", test_view),
    path("public/", public_view, name="public"),
    path("public_external/", public_external_view, name="public_external"),
    path("decorator_protected/", decorator_protected_view, name="decorator_protected"),
    path(
        "middleware_protected/", middleware_protected_view, name="middleware_protected"
    ),
    path(
        "azure_auth/",
        include("azure_auth.urls"),
    ),
]
