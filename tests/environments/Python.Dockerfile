FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b
RUN pip install --no-cache-dir uv==0.12.20 poetry==2.5.1 pdm==2.29.2 pipenv==2026.8.0
