from http import HTTPStatus

import msal
import requests
from django.conf import settings
from django.contrib.auth import get_user_model

from azure_auth.exceptions import DjangoAzureAuthException, TokenError

UserModel = get_user_model()


class AuthHandler:
    """
    Class to interface with `msal` package and execute authentication process.
    """

    def __init__(self, request=None):
        """

        :param request: HttpRequest
        """
        self.request = request
        self.graph_user_endpoint = "https://graph.microsoft.com/v1.0/me"
        self.auth_flow_session_key = "auth_flow"
        self._cache = msal.SerializableTokenCache()
        self._msal_app = None

    def get_auth_uri(self) -> str:
        """
        Requests the auth flow dictionary and stores it on the session to be
        queried later in the auth process.

        :return: Authentication redirect URI
        """
        # TODO: Handle if user has put incorrect details in settings
        flow = self.msal_app.initiate_auth_code_flow(
            scopes=settings.AZURE_AUTH["SCOPES"],
            redirect_uri=settings.AZURE_AUTH["REDIRECT_URI"],
        )
        self.request.session[self.auth_flow_session_key] = flow
        return flow["auth_uri"]

    def get_token_from_flow(self) -> dict:
        """
        Acquires the token from the auth flow on the session and the content of
        the redirect request from Active Directory.

        :return: Token result containing `access_token`/`id_token` and other
        claims, depending on scopes used
        """
        flow = self.request.session.pop(self.auth_flow_session_key, {})
        token_result = self.msal_app.acquire_token_by_auth_code_flow(
            auth_code_flow=flow, auth_response=self.request.GET
        )
        if "error" in token_result:
            raise TokenError(token_result["error"], token_result["error_description"])
        self._save_cache()
        self.request.session["id_token_claims"] = token_result["id_token_claims"]
        return token_result

    def get_token_from_cache(self):
        accounts = self.msal_app.get_accounts()
        if accounts:  # pragma: no branch
            # Will return `None` if CCA cannot retrieve or generate new token
            token_result = self.msal_app.acquire_token_silent(
                scopes=settings.AZURE_AUTH["SCOPES"], account=accounts[0]
            )
            self._save_cache()
            return token_result

    def authenticate(self, token: dict) -> UserModel:
        """
        Helper method to authenticate the user. Gets the Azure user from the
        Microsoft Graph endpoint and gets/creates the associated Django user.

        :param token: MSAL auth token dictionary
        :return: Django user instance
        """
        azure_user = self._get_azure_user(token["access_token"])

        # Allow for `outlook.com` users with email set on the
        # `userPrincipalName` attribute
        email = (
            azure_user["mail"]
            if azure_user.get("mail", None)
            else azure_user["userPrincipalName"]
        )

        # Using `UserModel._default_manager.get_by_natural_key` handles custom
        # user model and `USERNAME_FIELD` setting
        try:
            user = UserModel._default_manager.get_by_natural_key(email)
        except UserModel.DoesNotExist:
            user = UserModel._default_manager.create_user(username=email, email=email)
            user.first_name = attr if (attr := azure_user["givenName"]) else ""
            user.last_name = attr if (attr := azure_user["surname"]) else ""
            user.save()

        # TODO: Handle groups
        return user

    @staticmethod
    def get_logout_uri() -> str:
        """
        Forms the URI to log the user out in the Active Directory app and
        redirect to the webapp logout page.

        :return: Active Directory app logout URI
        """
        authority = settings.AZURE_AUTH["AUTHORITY"]
        logout_uri = settings.AZURE_AUTH.get("LOGOUT_URI", "")
        if logout_uri:
            return (
                f"{authority}/oauth2/v2.0/logout?post_logout_redirect_uri={logout_uri}"
            )
        return f"{authority}/oauth2/v2.0/logout"

    @property
    def msal_app(self):
        if self._msal_app is None:
            self._msal_app = msal.ConfidentialClientApplication(
                client_id=settings.AZURE_AUTH["CLIENT_ID"],
                client_credential=settings.AZURE_AUTH["CLIENT_SECRET"],
                authority=settings.AZURE_AUTH["AUTHORITY"],
                token_cache=self.cache,
            )
        return self._msal_app

    @property
    def cache(self):
        if self.request.session.get("token_cache"):
            self._cache.deserialize(self.request.session["token_cache"])
        return self._cache

    def _save_cache(self):
        if self.cache.has_state_changed:
            self.request.session["token_cache"] = self.cache.serialize()

    def _get_azure_user(self, token: str):
        resp = requests.get(
            self.graph_user_endpoint, headers={"Authorization": f"Bearer {token}"}
        )
        if resp.ok:
            return resp.json()
        elif resp.status_code == HTTPStatus.UNAUTHORIZED:
            error = resp.json()["error"]
            raise TokenError(message=error["code"], description=error["message"])
        else:  # pragma: no cover
            raise DjangoAzureAuthException("An unknown error occurred.")
