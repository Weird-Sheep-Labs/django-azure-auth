import pytest
from django.contrib.auth import get_user_model
from mixer.backend.django import mixer

UserModel = get_user_model()


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture(scope="function", autouse=True)
def user(request):
    _user = mixer.blend(UserModel)
    _user.username = _user.email
    _user.save()

    if request.cls:
        request.cls.user = _user
    return _user


@pytest.fixture(scope="function")
def auth_flow(request):
    _auth_flow = {
        "state": "dummy_state",
        "redirect_uri": "http://localhost:8000/azure_auth/callback",
        "scope": ["profile", "offline_access", "User.Read", "openid"],
        "auth_uri": "https://aad-auth-uri.com",
    }

    if request.cls:
        request.cls.auth_flow = _auth_flow
    return _auth_flow


@pytest.fixture(scope="function")
def token(request):
    _token = {
        "token_type": "Bearer",
        "scope": "openid profile User.Read email",
        "expires_in": 3749,
        "ext_expires_in": 3749,
        "access_token": "dummy_access_token",
        "refresh_token": "dummy_refresh_token",
        "id_token": "dummy_id_token",
        "client_info": "dummy_client_info",
    }

    if request.cls:
        request.cls.token = _token
    return _token
