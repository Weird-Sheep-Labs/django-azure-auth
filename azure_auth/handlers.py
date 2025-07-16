import datetime
import importlib
from http import HTTPStatus
from typing import Optional, cast
from urllib import parse

import msal
import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser, Group
from django.http import HttpRequest

from azure_auth.exceptions import DjangoAzureAuthException, TokenError

UserModel = cast(AbstractBaseUser, get_user_model())


class AuthHandler:
    """
    Class to interface with `msal` package and execute authentication process.
    """

    def __init__(self, request: HttpRequest):
        """

        :param request: HttpRequest
        """
        self.request = request
        self.graph_user_endpoint = settings.AZURE_AUTH.get(
            "GRAPH_USER_ENDPOINT", "https://graph.microsoft.com/v1.0/me"
        )
        self.auth_flow_session_key = "auth_flow"
        self._cache = msal.SerializableTokenCache()
        self._msal_app = None

        # Eagerly load the claims from the session
        self.claims = self.request.session.get("id_token_claims", {})

    def get_auth_uri(self, state: Optional[str] = None) -> str:
        """
        Requests the auth flow dictionary and stores it on the session to be
        queried later in the auth process.

        :param state: State to persist during log in
        :return: Authentication redirect URI
        """
        redirect_uri = self._get_redirect_uri()
        flow = self.msal_app.initiate_auth_code_flow(
            scopes=settings.AZURE_AUTH["SCOPES"],
            redirect_uri=redirect_uri,
            state=state,
            prompt=settings.AZURE_AUTH.get("PROMPT", None),
        )
        self.request.session[self.auth_flow_session_key] = flow
        return flow["auth_uri"]

    def get_token_from_flow(self):
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

            # `acquire_token_silent` doesn't always return ID token/ID token claims
            # https://github.com/AzureAD/microsoft-authentication-library-for-python/issues/139
            if token_result and token_result.get("id_token_claims"):
                self.request.session["id_token_claims"] = token_result[
                    "id_token_claims"
                ]
            return token_result

    def authenticate(self, token: dict) -> AbstractBaseUser:
        """
        Helper method to authenticate the user. Gets the Azure user from the
        Microsoft Graph endpoint and gets/creates the associated Django user.

        :param token: MSAL auth token dictionary
        :return: Django user instance
        """
        azure_user = self._get_azure_user(token["access_token"])

        # Get extra fields
        extra_fields = {}
        if fields := settings.AZURE_AUTH.get("EXTRA_FIELDS"):  # pragma: no branch
            extra_fields = self._get_azure_user(token["access_token"], fields=fields)

        # Combine user profile attributes, extra attributes and ID token claims
        # https://learn.microsoft.com/en-us/entra/external-id/customers/concept-user-attributes
        # https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
        attributes = {**azure_user, **extra_fields, **token.get("id_token_claims", {})}
        natural_key = attributes[settings.AZURE_AUTH["USERNAME_ATTRIBUTE"]]
        try:
            user = UserModel._default_manager.get_by_natural_key(natural_key)  # type: ignore

            # Sync Django user with AAD attributes
            self._update_user(user, **attributes)
        except UserModel.DoesNotExist:
            user = UserModel._default_manager.create_user(  # type: ignore
                **{UserModel.USERNAME_FIELD: natural_key},  # type: ignore
                **self._map_attributes_to_user(**attributes),
            )

        user = self.sync_groups(user, token)

        return user

    # Syncing azure token claim roles with django user groups
    # A role mapping in the AZURE_AUTH settings is expected.
    # The attribute of the token to use for group membership can be specified
    #   in AZURE_AUTH.GROUP_ATTRIBUTE
    def sync_groups(self, user, token):
        role_mappings = settings.AZURE_AUTH.get("ROLES")
        groups_attr = settings.AZURE_AUTH.get("GROUP_ATTRIBUTE", "roles")
        azure_token_roles = token.get("id_token_claims", {}).get(groups_attr, None)
        if role_mappings:  # pragma: no branch
            for role, group_names in role_mappings.items():
                if not isinstance(group_names, list):
                    group_names = [group_names]
                for group_name in group_names:
                    if not group_name:
                        continue  # Skip empty group names
                    # all groups are created by default if they not exist
                    django_group = Group.objects.get_or_create(name=group_name)[0]

                    if azure_token_roles and role in azure_token_roles:
                        # Add user with permissions to the corresponding django group
                        user.groups.add(django_group)
                    else:
                        # No permission so check if user is in group and remove
                        if user.groups.filter(name=group_name).exists():
                            user.groups.remove(django_group)

        return user

    def get_logout_uri(self) -> str:
        """
        Forms the URI to log the user out in the Active Directory app and
        redirect to the webapp logout page.

        :return: Active Directory app logout URI
        """
        authority = settings.AZURE_AUTH["AUTHORITY"]
        _query_params = {
            "post_logout_redirect_uri": settings.AZURE_AUTH.get("LOGOUT_URI"),
            "logout_hint": self.claims.get("login_hint"),
        }
        query_params = {k: v for k, v in _query_params.items() if v}
        return f"{authority}/oauth2/v2.0/logout?{parse.urlencode(query_params)}"

    @property
    def user_is_authenticated(self) -> bool:
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()

        # Check the ID token is still valid in the first instance
        if now < self.claims.get("exp", 0) and self.request.user.is_authenticated:
            return True

        # Otherwise try refresh the token
        return (
            self.get_token_from_cache() is not None
            and self.request.user.is_authenticated
        )

    def _get_confidential_client(self):
        secret = settings.AZURE_AUTH.get("CLIENT_SECRET", "<client_secret>")
        if secret == "<client_secret>":
            raise DjangoAzureAuthException(
                "CLIENT_TYPE='confidential_client' also requires CLIENT_SECRET to be set in AZURE_AUTH"
            )
        additional_kwargs = settings.AZURE_AUTH.get("ADDITIONAL_CLIENT_KWARGS", {})
        return msal.ConfidentialClientApplication(
            client_id=settings.AZURE_AUTH["CLIENT_ID"],
            client_credential=settings.AZURE_AUTH["CLIENT_SECRET"],
            authority=settings.AZURE_AUTH["AUTHORITY"],
            token_cache=self.cache,
            **additional_kwargs,
        )

    def _get_public_client(self):
        additional_kwargs = settings.AZURE_AUTH.get("ADDITIONAL_CLIENT_KWARGS", {})
        return msal.PublicClientApplication(
            client_id=settings.AZURE_AUTH["CLIENT_ID"],
            authority=settings.AZURE_AUTH["AUTHORITY"],
            token_cache=self.cache,
            **additional_kwargs,
        )

    @property
    def msal_app(self):
        if self._msal_app is None:
            client_type = settings.AZURE_AUTH.get("CLIENT_TYPE", "confidential_client")
            if client_type == "confidential_client":
                self._msal_app = self._get_confidential_client()
            elif client_type == "public_client":
                self._msal_app = self._get_public_client()
            else:
                raise DjangoAzureAuthException(
                    f"Invalid CLIENT_TYPE '{client_type}' specified in AZURE_AUTH settings."
                )
        return self._msal_app

    @property
    def cache(self):
        if self.request.session.get("token_cache"):  # pragma: no branch
            self._cache.deserialize(self.request.session["token_cache"])
        return self._cache

    def _save_cache(self):
        if self.cache.has_state_changed:
            self.request.session["token_cache"] = self.cache.serialize()

    def _get_azure_user(self, token: str, fields: Optional[dict] = None):
        params = {"$select": ",".join(fields)} if fields else None
        resp = requests.get(
            self.graph_user_endpoint,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
        )
        if resp.ok:
            return resp.json()
        elif resp.status_code == HTTPStatus.UNAUTHORIZED:
            error = resp.json()["error"]
            raise TokenError(message=error["code"], description=error["message"])
        else:  # pragma: no cover
            raise DjangoAzureAuthException("An unknown error occurred.")

    def _map_attributes_to_user(self, **fields) -> dict:
        if user_mapping_fn := settings.AZURE_AUTH.get(
            "USER_MAPPING_FN"
        ):  # pragma: no branch
            path, fn = user_mapping_fn.rsplit(".", 1)
            mod = importlib.import_module(path)
            return getattr(mod, fn)(**fields)
        return {}  # pragma: no cover

    def _update_user(self, user: AbstractBaseUser, **fields):
        if user_mapping_fn := settings.AZURE_AUTH.get(  # pragma: no branch
            "USER_MAPPING_FN"
        ):
            path, fn = user_mapping_fn.rsplit(".", 1)
            mod = importlib.import_module(path)
            for field, value in getattr(mod, fn)(**fields).items():
                setattr(user, field, value)
            user.save()

    def _get_redirect_uri(self) -> str:
        redirect_uri = settings.AZURE_AUTH["REDIRECT_URI"]
        if not isinstance(redirect_uri, str):
            # Resolve the URI when it's a reverse_lazy callable
            redirect_uri = str(redirect_uri)
        if not redirect_uri.startswith("http"):
            redirect_uri = self.request.build_absolute_uri(redirect_uri)
        return redirect_uri
