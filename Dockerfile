FROM python:3.14-slim-bookworm

ENV UV_LINK_MODE=copy

COPY --from=ghcr.io/astral-sh/uv:0.9.28 /uv /uvx /bin/

WORKDIR /code

COPY . /code

RUN uv sync --locked --group dev
