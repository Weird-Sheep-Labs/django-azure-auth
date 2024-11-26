from django.apps import AppConfig
from django.conf import settings
from django.core.checks import Error, register


@register()
def azure_auth_check(app_configs, **kwargs):
    errors = []

    if not settings.AZURE_AUTH.get("USERNAME_ATTRIBUTE"):
        errors.append(
            Error(
                "misconfigured settings",
                hint="Specify a value for `USERNAME_ATTRIBUTE`.",
                obj=settings.AZURE_AUTH,
                id="azure_auth.E001",
            )
        )
    return errors


class AzureAuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "azure_auth"
