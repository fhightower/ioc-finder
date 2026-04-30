.PHONY: clean clean-test clean-pyc clean-build docs help init install lint test test-all coverage dist pypi
.DEFAULT_GOAL := help
define BROWSER_PYSCRIPT
import os, webbrowser, sys
try:
	from urllib import pathname2url
except:
	from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT
BROWSER := python -c "$$BROWSER_PYSCRIPT"

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

UV := uv

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts


clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/

lint: ## check style with ruff and mypy
	$(UV) run ruff check ioc_finder tests
	$(UV) run mypy ioc_finder tests

test: ## run tests quickly with the default Python
	$(UV) run pytest
	

test-all: ## run tests on every Python version with tox
	$(UV) run pytest

coverage: ## check code coverage quickly with the default Python
	$(UV) run coverage run --source ioc_finder -m pytest
	
		$(UV) run coverage report -m
		$(UV) run coverage html
		$(BROWSER) htmlcov/index.html

docs: ## generate Sphinx HTML documentation, including API docs
	rm -f docs/ioc_finder.rst
	rm -f docs/modules.rst
	sphinx-apidoc -o docs/ ioc_finder
	$(MAKE) -C docs clean
	$(MAKE) -C docs html
	$(BROWSER) docs/_build/html/index.html

servedocs: docs ## compile the docs watching for changes
	watchmedo shell-command -p '*.rst' -c '$(MAKE) -C docs html' -R -D .

release: clean ## package and upload a release
	$(UV) build
	$(UV) publish

dist: clean ## builds source and wheel package
	$(UV) build
	ls -l dist

install: clean ## install the package to the active Python's site-packages
	$(UV) sync --locked --group dev

upstream: ## set the upstream for the repository
	git remote set-upstream https://github.com/fhightower/ioc-finder.git

init: ## install the project and development requirements with uv
	$(UV) sync --locked --group dev

pypi: clean ## upload the code to pypi
	$(UV) build
	$(UV) publish
