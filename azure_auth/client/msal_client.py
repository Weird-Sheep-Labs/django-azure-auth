import msal
import requests
from django.conf import settings
from django.contrib.auth import get_user_model

UserModel = get_user_model()


class MSALClient:
    # TODO: Docs
    def __init__(self, request=None):
        self.request = request
        self.graph_user_endpoint = "https://graph.microsoft.com/v1.0/me"
        self.auth_flow_session_key = "auth_flow"
        self._cache = None
        self._msal_app = None

    def get_flow(self):
        # TODO: Handle possible error
        flow = self.msal_app.initiate_auth_code_flow(
            scopes=settings.AZURE_AUTH["SCOPES"],
            redirect_uri=settings.AZURE_AUTH["REDIRECT_URI"],
        )
        self.request.session[self.auth_flow_session_key] = flow
        return flow

    def authenticate(self):
        token_result = self._get_token_from_flow()
        azure_user = self._get_azure_user(token_result["access_token"])
        email = azure_user["mail"]

        # Using `UserModel._default_manager.get_by_natural_key` handles custom
        # user model and `USERNAME_FIELD` setting
        try:
            user = UserModel._default_manager.get_by_natural_key(email)
        except UserModel.DoesNotExist:
            user = UserModel._default_manager.create_user(username=email, email=email)
            user.is_staff = True
            user.save()

        # TODO: Handle groups
        return user

    @property
    def logout_url(self):
        authority = settings.AZURE_AUTH["AUTHORITY"]
        logout_uri = settings.AZURE_AUTH["LOGOUT_URI"]
        return (
            f"{authority}/oauth2/v2.0/logout" f"?post_logout_redirect_uri={logout_uri}"
        )

    @property
    def msal_app(self):
        if self._msal_app is None:
            self._msal_app = msal.ConfidentialClientApplication(
                settings.AZURE_AUTH["CLIENT_ID"],
                authority=settings.AZURE_AUTH["AUTHORITY"],
                client_credential=settings.AZURE_AUTH["CLIENT_SECRET"],
                token_cache=self.cache,
            )
        return self._msal_app

    @property
    def cache(self):
        _cache = msal.SerializableTokenCache()
        if self.request.session.get("token_cache"):
            _cache.deserialize(self.request.session["token_cache"])
        self._cache = _cache
        return self._cache

    def _save_cache(self):
        if self.cache.has_state_changed:
            self.request.session["token_cache"] = self.cache.serialize()

    def _get_token_from_flow(self):
        flow = self.request.session.pop(self.auth_flow_session_key, {})
        # TODO: Handle possible error
        token_result = self.msal_app.acquire_token_by_auth_code_flow(
            flow, self.request.GET
        )
        self._save_cache()
        return token_result

    def _get_azure_user(self, token):
        resp = requests.get(
            self.graph_user_endpoint, headers={"Authorization": f"Bearer {token}"}
        )
        # TODO: Handle bad response
        if resp.ok:
            return resp.json()
