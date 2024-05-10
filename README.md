![Build](https://github.com/Weird-Sheep-Labs/django-azure-auth/actions/workflows/ci.yml/badge.svg)
![Coverage Status](./reports/coverage/coverage-badge.svg?dummy=8484744)
[![PyPI downloads](https://img.shields.io/pypi/dm/django-azure-auth.svg)](https://pypistats.org/packages/django-azure-auth)

# django-azure-auth

### A simple Django app for user authentication with Azure Active Directory/Entra ID.

by [Weird Sheep Labs](https://weirdsheeplabs.com)

<a target="_blank" href="https://weirdsheeplabs.com"><img src="https://weirdsheeplabs.com/android-chrome-192x192.png" height="40" width="40" /></a>

#### Naming update

In March 2024, [Microsoft renamed Azure Active Directory (Azure AD) to Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/fundamentals/new-name).

## Description

`django-azure-auth` is a Django app which wraps the great [MSAL](https://github.com/AzureAD/microsoft-authentication-library-for-python)
package to enable authentication against Microsoft's Azure Active Directory in Django projects.

The app includes `login`, `logout` and `callback` authentication views, a decorator
to protect individual views, and middleware which allows the entire site to require user
authentication by default, with the ability to exempt specified views.

This project is in no way affiliated with Microsoft.

## Installation

From PyPi:

```bash
pip install django-azure-auth
```

## Configuration

### Azure setup

- Register an app at https://portal.azure.com/.
- Add a client secret and note it down.
- Add a redirect URI of the format `https://<domain>/azure_auth/callback`.

### Settings

Add the following to your `settings.py`, replacing the variables in braces with the values
from your Azure app:

```python
AZURE_AUTH = {
    "CLIENT_ID": "<client id>",
    "CLIENT_SECRET": "<client secret>",
    "REDIRECT_URI": "https://<domain>/azure_auth/callback",
    "SCOPES": ["User.Read"],
    "AUTHORITY": "https://login.microsoftonline.com/<tenant id>",   # Or https://login.microsoftonline.com/common if multi-tenant
    "LOGOUT_URI": "https://<domain>/logout",    # Optional
    "PUBLIC_URLS": ["<public:view_name>",],  # Optional, public views accessible by non-authenticated users
    "PUBLIC_PATHS": ['/go/',],  # Optional, public paths accessible by non-authenticated users
    "ROLES": {
        "95170e67-2bbf-4e3e-a4d7-e7e5829fe7a7": "GroupName1",
        "3dc6539e-0589-4663-b782-fef100d839aa": "GroupName2"
    }  # Optional, will add user to django group if user is in EntraID group
}
LOGIN_URL = "/azure_auth/login"
LOGIN_REDIRECT_URL = "/"    # Or any other endpoint
```

#### Note: You should obfuscate the credentials by using environment variables.

### Installed apps

Add the following to your `INSTALLED_APPS`:

```python
INSTALLED_APPS = (
    "...",
    "azure_auth",
    "..."
)
```

### Authentication backend

Configure the authentication backend:

```python
AUTHENTICATION_BACKENDS = ("azure_auth.backends.AzureBackend",)
```

### URLs

Include the app's URLs in your `urlpatterns`:

```python
from django.urls import path, include

urlpatterns = [
    path("azure_auth/", include("azure_auth.urls"),),
]
```

## Usage

### Decorator

To make user authentication a requirement for accessing an individual view, decorate the
view like so:

```python
from azure_auth.decorators import azure_auth_required
from django.shortcuts import HttpResponse

@azure_auth_required
def protected_view(request):
    return HttpResponse("A view protected by the decorator")
```

### Middleware

If you want to protect your entire site by default, you can use the middleware by adding the
following to your `settings.py`:

```python
MIDDLEWARE = [
    "...",
    "azure_auth.middleware.AzureMiddleware",
    "...",
]
```

Make sure you add the middleware after Django's `session` and `authentication` middlewares so
that the request includes the session and user objects. Public URLs which need to be accessed by
non-authenticated users should be specified in the `settings.AZURE_AUTH["PUBLIC_URLS"]`, as
shown above.

## Groups Management

Adding a group to the Azure Enterprise application will pass the group id down to the application via the token.
This happens only, if the user is part of the group. In this case the group will be listed in the `token`.

On how to configure this in Azure see here: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims

Groups available in the token are synced with the corresponding django groups. Therfor the group id's from Azure need to be mapped in the
settings with the Django groups by adding the following to `AZURE_AUTH` in `settings`.

```
"ROLES": {
        "95170e67-2bbf-4e3e-a4d7-e7e5829fe7a7": "GroupName1",
        "3dc6539e-0589-4663-b782-fef100d839aa": "GroupName2"
    }
```

If a user is assigned to one or more of this groups listed in the configuration, the user will be added
automatically to the respective Django group. The group will be created if it does not exist.
If a user is not part of a group (revoke permissions case), but is still in the Django group, the user
will be removed from the Django group.

## Bypass logout account selection

During logout, if the ID token includes only the default claims, Active Directory will present the user with a page prompting them to select the account to log out. To disable this, simply enable the `login_hint` optional claim in your client application in Azure, as described in https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc#send-a-sign-out-request.

## Credits

This app is heavily inspired by and builds on functionality in
https://github.com/shubhamdipt/django-microsoft-authentication, with both feature
improvements and code assurance through testing.

Credit also to:

- https://github.com/Azure-Samples/ms-identity-python-webapp
- https://github.com/AzMoo/django-okta-auth

<div align="center">
    <a target="_blank" href="https://weirdsheeplabs.com"><img src="https://weirdsheeplabs.com/android-chrome-192x192.png" height="50" width="50" /></a>
</div>
