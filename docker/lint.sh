#!/usr/bin/env bash

set -euxo pipefail

echo "Running linters and formatters..."

isort ioc_finder/ tests/

black ioc_finder/ tests/

mypy ioc_finder/ tests/

pylint --fail-under 9 ioc_finder/*.py

flake8 ioc_finder/
