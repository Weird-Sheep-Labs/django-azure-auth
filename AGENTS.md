# AGENTS.md

## Toolchain

- Package manager: **uv** (not pip/poetry). All commands go through `uv run` or `uv sync`.
- Python version: **3.14** (set in `.python-version`). `requires-python = ">=3.10"` in `pyproject.toml` is a floor, not a target.
- Build backend: `uv_build`. Flat package layout: `azure_auth/` at repo root.

## Package layout

```
azure_auth/
  apps.py
  backends.py
  decorators.py
  exceptions.py
  handlers.py
  middleware.py
  urls.py
  utils.py
  views.py
  tests/
```

## Common commands

```bash
uv sync --all-groups               # install runtime + dev deps
uv run pytest                      # run all tests
uv run pre-commit run -a           # lint + format + lockfile checks
uv run ty check                    # type checking (ty, not mypy)
uv build                           # build wheel/sdist for PyPI
```

Coverage is on by default (`--cov` in `pyproject.toml`). Pass `--no-cov` to skip it when iterating.

Run `uv run ty check` and `uv run ruff check --fix` after every code change.

## CI

- `test.yaml` — runs `pre-commit` + `ty check` + `pytest` on push/PR; tests Python 3.10–3.14 matrix.
- `release.yml` — triggers on `Test` workflow success on `main`; runs `semantic-release` (prerelease on auto, full release on `workflow_dispatch`).

Commit messages must follow **Conventional Commits** (enforced by `conventional-pre-commit` hook).

## Pre-commit hooks (in order)

1. `conventional-pre-commit` (commit-msg)
2. `ruff-check --fix`
3. `ruff-format`
4. `pyproject-fmt`
5. `uv-lock`
