#!/bin/bash
# Helper script for installing poetry on pipeline
curl -sSL https://install.python-poetry.org | python3 -
export PATH="/root/.local/bin:$PATH"