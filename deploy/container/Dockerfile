FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /app

RUN groupadd --system mirage && useradd --system --gid mirage --uid 10001 mirage
COPY --from=builder /wheels /wheels
COPY requirements.txt requirements.txt
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

COPY mirage /app/mirage
COPY config.json /app/config.json
USER 10001:10001

EXPOSE 8000
CMD ["python", "-m", "mirage.api.server", "--host", "0.0.0.0", "--port", "8000"]
