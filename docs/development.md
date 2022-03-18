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

# Questions? Please Ask!

If you have any follow-up questions, don't hesitate to ask! It takes practice to understand how to contribute to open-source software, so there is no shame in asking for help.

[pytest-link]: https://docs.pytest.org/en/stable/
[docker-compose]: https://docs.docker.com/compose/
[docker-install]: https://docs.docker.com/get-docker/
[docker]: https://www.docker.com/get-started
[linting-intro]: https://dbader.org/blog/python-code-linting
[ipython]: https://ipython.org/

