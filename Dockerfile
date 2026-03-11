FROM python:3.10.2-buster

ENV UV_LINK_MODE=copy

COPY --from=ghcr.io/astral-sh/uv:0.9.28 /uv /uvx /bin/

WORKDIR /code

COPY . /code

RUN uv sync --locked --group dev
