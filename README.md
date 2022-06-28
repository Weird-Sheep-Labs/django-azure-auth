![Build](https://github.com/AgileTek/django-azure-auth/actions/workflows/push-actions.yml/badge.svg)

# Django Azure Auth
A simple Django app for user authentication with Azure Active Directory.

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
    "PUBLIC_URLS": ["<public:view_name>",]  # Optional, public views accessible by non-authenticated users
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

## Planned development
- Groups management

## Credits
This app is heavily inspired by and builds on functionality in 
https://github.com/shubhamdipt/django-microsoft-authentication, with both feature 
improvements and code assurance through testing.

Credit also to:
- https://github.com/Azure-Samples/ms-identity-python-webapp
- https://github.com/AzMoo/django-okta-auth