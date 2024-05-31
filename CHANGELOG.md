# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Auth handler no longer assumes the user model includes `first_name` and `last_name` fields.
- Users can now completely customize the mapping of AAD attributes to Django User model fields.

## [1.4.3] - 2024-05-31

### Fixed

- Fixed login callback redirect bug caused by AAD `state` parameter being populated by Azure AD when empty (#30).

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
