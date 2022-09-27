#!/usr/bin/env bash

set -euxo pipefail

echo "Running linters and formatters..."

isort ioc_finder/ tests/

black ioc_finder/ tests/

# if the CONTEXT env var is "ci" (which is set in .github/workflows/lint.yml), validate that none of the files
# have been changed by the previous lint steps
if [ "${CONTEXT:-local}" = "ci" ]; then
    (git status | grep "nothing to commit") || { echo "Lint steps have changed files"; exit 1; };
fi

mypy ioc_finder/ tests/

pylint --fail-under 9 ioc_finder/*.py

flake8 ioc_finder/

echo "Done ✨ 🎉 ✨"

