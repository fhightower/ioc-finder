# Development Guide 🐳

This page shows you how to test, lint, and explore the ioc-finder.
As always, if you have feedback, please [raise an issue](https://github.com/fhightower/ioc-finder/issues/new) and we'll be happy
to improve our docs. Thanks!

## Prerequisites

If you want to test, lint, or explore ioc-finder, make sure you have [docker][docker] and [docker-compose][docker-compose] installed (if you don't see: [installing docker][docker-install]).

Then you can use the `test`, `lint`, and `dev` docker compose services listed below!

## Test ioc-finder 🧪

To test ioc-finder, run the following command from the root directory of the project:

```shell
docker-compose run --rm test
```

Typically, this command will run [pytest][pytest-link] on the project's test suite. To view the details of what this command does, take a look at the `test` service in the project's `docker-compose.yml` file.

### Understanding our Testing Framework

There are two types of tests in the `ioc-finder/tests/` directory:

1. Standard tests is test_*.py files
2. Tests run by `ioc-finder/tests/test_find_iocs.py`

In this section of the documentation, we'll discuss the second set of tests (those run by `ioc-finder/tests/test_find_iocs.py`).

In the `ioc-finder/tests/find_iocs_cases` dir, there are files which define test cases with an input and expected output for different types of observables (a.k.a. indicators).

A test case is a [`pytest.param`](https://docs.pytest.org/en/stable/reference/reference.html?highlight=The%20id%20to%20attribute%20to%20this%20parameter%20set#pytest.param) object
that takes these arguments:

- The input to the `ioc_finder.find_iocs` function (a string)
- The expected output from the `ioc_finder.find_iocs` function (a dict)
- (*Optional*) Kwargs for the `ioc_finder.find_iocs` function (a dict)
- The `id` kwarg providing a name for the test (a string)

`ioc-finder/tests/test_find_iocs.py` collects data from the `ioc-finder/tests/find_iocs_cases` dir and runs tests to make sure the `find_iocs` function returns the expected data.

## Lint ioc-finder 🧹

To lint ioc-finder, run the following command from the root directory of the project:

```shell
docker-compose run --rm lint
```

Typically, this command will run a number of linters on the project's code with the goal of improving code qality and catching bugs before they are released (you can read more about the benefits of linting [here][linting-intro]). To view the details of what this command does, take a look at the `lint` service in the project's `docker-compose.yml` file.

## Explore ioc-finder 🔭

To explore ioc-finder, you can drop into a "dev" environment which is an [IPython][ipython] shell with the project and all its requirements loaded. To do this, run the following command from the root directory of the project:

```shell
docker-compose run --rm dev
```

To see what this command does, take a look at the `dev` service in the project's `docker-compose.yml` file.

## Run Docs Locally 📖

To view the docs for ioc-finder locally, run the following command from the root directory of the project:

```shell
docker-compose run --rm mkdocs
```

This will serve the documentation at `http://localhost:8000`.

# Questions? Please Ask!

If you have any follow-up questions, don't hesitate to ask! It takes practice to understand how to contribute to open-source software, so there is no shame in asking for help.

[pytest-link]: https://docs.pytest.org/en/stable/
[docker-compose]: https://docs.docker.com/compose/
[docker-install]: https://docs.docker.com/get-docker/
[docker]: https://www.docker.com/get-started
[linting-intro]: https://dbader.org/blog/python-code-linting
[ipython]: https://ipython.org/

