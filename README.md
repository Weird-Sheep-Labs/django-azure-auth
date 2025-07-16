![Build](https://github.com/Weird-Sheep-Labs/django-azure-auth/actions/workflows/ci.yml/badge.svg)
![Coverage Status](./reports/coverage/coverage-badge.svg?dummy=8484744)
[![PyPI downloads](https://img.shields.io/pypi/dm/django-azure-auth.svg)](https://pypistats.org/packages/django-azure-auth)
[![PyPI Downloads](https://static.pepy.tech/badge/django-azure-auth)](https://pepy.tech/projects/django-azure-auth)

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
    "CLIENT_TYPE": "confidential_client", # Optional, pick "public_client" or "confidential_client" (default)
    "CLIENT_SECRET": "<client secret>", # optional for public clients
    # REDIRECT_URI must be set to one of
    # - an absolute URI starting with "http" or "https", e. g. https://<domain>/azure_auth/callback
    # - a relative URI starting with "/", e. g. /azure_auth/callback
    # - a call to reverse_lazy, e. g. reverse_lazy("azure_auth:callback")
    "REDIRECT_URI": "https://<domain>/azure_auth/callback",
    "SCOPES": ["User.Read"],
    "PROMPT": "select_account",  # Optional, one of "login", "consent", "select_account", "none" (default)
    #"ADDITIONAL_CLIENT_KWARGS": {"enable_broker_on_windows": True}, # Optional: additional KWARGS to give to public and confidential client
    "AUTHORITY": "https://login.microsoftonline.com/<tenant id>",   # Or https://login.microsoftonline.com/common if multi-tenant
    "LOGOUT_URI": "https://<domain>/logout",    # Optional
    "PUBLIC_URLS": ["<public:view_name>",],  # Optional, public views accessible by non-authenticated users
    "PUBLIC_PATHS": ['/go/',],  # Optional, public paths accessible by non-authenticated users
    "ROLES": {
        "95170e67-2bbf-4e3e-a4d7-e7e5829fe7a7": "GroupName1", # mapped to one Django group
        "3dc6539e-0589-4663-b782-fef100d839aa": ["GroupName2", "GroupName3"] # mapped to multiple Django groups
    },  # Optional, will add user to django group if user is in EntraID group
    "USERNAME_ATTRIBUTE": "mail",   # The AAD attribute or ID token claim you want to use as the value for the user model `USERNAME_FIELD`
    "GROUP_ATTRIBUTE": "roles",   # The AAD attribute or ID token claim you want to use as the value for the user's group memberships
    "EXTRA_FIELDS": [], # Optional, extra AAD user profile attributes you want to make available in the user mapping function
    "USER_MAPPING_FN": "azure_auth.tests.misc.user_mapping_fn", # Optional, path to the function used to map the AAD to Django attributes
    "GRAPH_USER_ENDPOINT": "https://graph.microsoft.com/v1.0/me", # Optional, URL to the Graph endpoint that returns user info
}
LOGIN_URL = "/azure_auth/login"
LOGIN_REDIRECT_URL = "/"    # Or any other endpoint
```

#### Note: You should obfuscate the credentials by using environment variables.

### Username field

Make sure you configure the `settings.AZURE_AUTH["USERNAME_ATTRIBUTE"]` setting to the AAD attribute or ID token claim you want to use for the `USERNAME_FIELD` of your user model. Common choices are `mail`, `sub` or `oid`.

> [!NOTE]
> In version 1.x.x this was hardcoded to `mail`.

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

### User attributes mapping

A common use-case is to save attributes/claims from AAD on fields of the Django user model. Rather than providing a way to configure a 1-to-1 mapping, `django-azure-auth` allows you to define a function that takes in the AAD attributes/claims and transform/compose them into Django user model values, in a completely customizable way. As an example, suppose you have the following user model:

```python
class User(AbstractUser):
    full_name = models.CharField()
```

You want to populate the `full_name` field using the `givenName` and `surname` AAD user attributes i.e not a 1-to-1 mapping. You also want to mark the user as staff.

You can do this by simply defining the below function and specifying the `settings.AZURE_AUTH["USER_MAPPING_FN"]` setting as the import path of the function:

```python
# main/utils.py

def user_mapping_fn(**attributes):
    return {
        "full_name": attributes["givenName"] + attributes["surname"],
        "is_staff": True,
    }
```

> [!NOTE]
> In this example, the `USER_MAPPING_FN` setting would be specified as "main.utils.user_mapping_fn".

The attributes passed to the mapping function will include:

- The default user profile attributes https://learn.microsoft.com/en-us/entra/external-id/customers/concept-user-attributes
- The ID token claims https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
- Any extra user attributes specified in `settings.AZURE_AUTH["EXTRA_FIELDS"]

> [!IMPORTANT]
> The mapping function **must** return a dictionary whose keys are all valid attributes/fields of your user model, otherwise an AttributeError will be raised during authentication.

### Groups management

Adding a group to the Azure Enterprise application will pass the group id down to the application via the `id_token`, provided that the user is part of the group.
On how to configure this optional group claim in Azure see here: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims

> [!NOTE]
> Note that the default key will be `groups` though while the app expects this information under the `roles` key of the `id_token`. To make sure that the group information is fed down as a role claim, select the **Emit groups as role claims** checkbox, when configuring the group claims (https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims#customize-group-claim-name). Alternatively, you can set `settings.AZURE_AUTH.GROUP_ATTRIBUTE = 'groups'` to use the default attribute

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

### Bypass logout account selection

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
