from typing import Any

import pytest
from django.contrib.auth import get_user_model
from mixer.backend.django import mixer

UserModel = get_user_model()


@pytest.fixture(scope="function", autouse=True)
def user(request):
    _user: Any = mixer.blend(UserModel)
    _user.username = _user.email
    _user.is_staff = False
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
        "id_token_claims": {
            "aud": "dummy_id_token_claims_aud",
            "iss": "dummy_id_token_claims_iss",
            "iat": 1655968842,
            "nbf": 1655968842,
            "exp": 1655972742,
            "aio": "dummy_id_token_claims_aio",
            "name": "dummy_id_token_claims_name",
            "nonce": "dummy_id_token_claims_nonce",
            "oid": "dummy_id_token_claims_oid",
            "preferred_username": "dummy_id_token_claims_preferred_username",
            "rh": "dummy_id_token_claims_rh",
            "sub": "dummy_id_token_claims_sub",
            "tid": "dummy_id_token_claims_tid",
            "uti": "dummy_id_token_claims_uti",
            "ver": "2.0",
            "roles": ["95170e67-2bbf-4e3e-a4d7-e7e5829fe7a7"],
            "login_hint": "dummy_id_token_claims_login_hint",
        },
    }

    if request.cls:
        request.cls.token = _token
    return _token
