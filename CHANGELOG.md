# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.4.0] - 2025-09-07

### Added

- Add ability to map multiple groups to an Entra role.
- Add public client handler.

## [2.3.0] - 2025-02-12

### Added

- Add ability to specify callback URL with `reverse_lazy`.

### Fixed

- Performance optimizations.

## [2.2.0] - 2024-12-14

### Changed

- Add optional setting to specify which Microsoft groups attribute to use i.e `roles` or `groups`.

## [2.1.0] - 2024-10-15

### Added

- Add optional setting for Graph API `/me` URL.

## [2.0.2] - 2024-09-03

### Fixed

- Validates that the `next` path is a relative path to only allow redirects within the host domain.

## [2.0.1] - 2024-09-02

### Fixed

- Auth handler correctly removes users from Django groups when the ID token `roles` claim is empty.

## [2.0.0] - 2024-06-08

### Fixed

- Auth handler no longer assumes the user model includes `first_name` and `last_name` fields ([#23](https://github.com/Weird-Sheep-Labs/django-azure-auth/issues/23)). This introduces a breaking change as these fields are no longer populated on the model by default.

### Changed

- Optional AAD attributes to be retrieved can be specified in the settings ([#11](https://github.com/Weird-Sheep-Labs/django-azure-auth/issues/11)).
- AAD attributes and ID token claims can be mapped to Django User model fields using a user-defined function ([#23](https://github.com/Weird-Sheep-Labs/django-azure-auth/issues/23)).

## [1.4.3] - 2024-05-31

### Fixed

- Fixed login callback redirect bug caused by AAD `state` parameter being populated by Azure AD when empty ([#30](https://github.com/Weird-Sheep-Labs/django-azure-auth/issues/30)).

## [1.4.2] - 2024-05-30

### Changed

- Change post-login redirect mechanism to use the AAD `state` parameter rather than the Django user session (#28).
- Include the redirect functionality for decorator-protected views, not just middleware-protected views (#28).

## [1.4.1] - 2024-05-29

### Changed

- Auth handler now checks the expiry of the ID token claims when authenticating a request, rather than requesting a token from MSAL on every request, massively reducing latency (#27).

## [1.4.0] - 2024-05-10

### Added

- This changelog!

### Changed

- Redirect to intended protected page after authentication and log in. Previously the user would always be redirected to the `LOGIN_REDIRECT_URL` (#25).

## [1.3.0] - 2024-04-27

### Changed

- Bypass account selection during logout. Previously a user would have to manually choose which account to log out due to AAD default behaviour, even though only one account would be logged in (#22).
