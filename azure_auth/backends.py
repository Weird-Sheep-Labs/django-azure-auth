from django.contrib.auth.backends import ModelBackend

from .handlers import AuthHandler


class AzureBackend(ModelBackend):
    def authenticate(self, request, token=None, *args, **kwargs):
        if not token:  # pragma: no cover
            return
        user = AuthHandler(request).authenticate(token)

        # Return only if `is_active`
        if self.user_can_authenticate(user):
            return user
