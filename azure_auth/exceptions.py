class DjangoAzureAuthException(Exception):
    pass


class TokenError(DjangoAzureAuthException):
    def __init__(self, message, description):
        self.message = message if message else ""
        self.description = description if description else ""

    def __str__(self):
        return f"{self.message}\n{self.description}"
