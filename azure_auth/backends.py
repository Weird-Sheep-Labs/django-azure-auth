from django.contrib.auth.backends import ModelBackend

from .handlers import AuthHandler


class AzureBackend(ModelBackend):
    def authenticate(self, request, token=None, *args, **kwargs):
        if not token:
            return
        user = AuthHandler(request).authenticate(token)
        if self.user_can_authenticate(user):
            return user
