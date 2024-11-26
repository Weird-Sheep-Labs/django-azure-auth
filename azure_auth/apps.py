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

    def ready(self) -> None:
        from django.contrib.auth.models import Group

        role_mappings = settings.AZURE_AUTH.get("ROLES")

        for group_name in role_mappings.values():
            Group.objects.get_or_create(name=group_name)

        return super().ready()
