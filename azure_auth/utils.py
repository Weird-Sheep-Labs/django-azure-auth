import json
from typing import Any

from django.conf import settings


class EntraStateSerializer:
    def serialize(self, **kwargs):
        return json.dumps(kwargs)

    def deserialize(self, state: str):
        try:
            return json.loads(state)
        except json.JSONDecodeError:
            return {}


def enable_broker_on_windows(azure_auth: dict[str, Any]) -> None:
    """
    Modifies the given azure_auth settings dictionary to enable brokered authentication.
    This assumes the current platform is Windows.

    For details, see:
        Using MSAL Python with Web Account Manager
        https://learn.microsoft.com/en-us/entra/msal/python/advanced/wam
    """

    # WAM only makes sense for public clients.  The Azure Portal also needs to have
    # the correct redirect URL configured:
    #   ms-appx-web://microsoft.aad.brokerplugin/YOUR_CLIENT_ID
    azure_auth["CLIENT_TYPE"] = "public_client"
    additional_client_kwargs = azure_auth.get("ADDITIONAL_CLIENT_KWARGS", {})
    additional_client_kwargs["enable_broker_on_windows"] = True
    azure_auth["ADDITIONAL_CLIENT_KWARGS"] = additional_client_kwargs


def is_broker_enabled() -> bool:
    """Returns True if brokered authentication is enabled in the settings,
    False otherwise."""
    return settings.AZURE_AUTH.get("ADDITIONAL_CLIENT_KWARGS", {}).get(
        "enable_broker_on_windows", False
    )
