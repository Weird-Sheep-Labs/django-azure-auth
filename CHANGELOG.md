# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Auth handler no longer assumes the user model includes `first_name` and `last_name` fields.

## [1.4.0] - 2024-05-10

### Added

- This changelog!

### Changed

- Redirect to intended protected page after authentication and log in. Previously the user would always be redirected to the `LOGIN_REDIRECT_URL` (#25).

## [1.3.0] - 2024-04-27

### Changed

- Bypass account selection during logout. Previously a user would have to manually choose which account to log out due to AAD default behaviour, even though only one account would be logged in (#22).
