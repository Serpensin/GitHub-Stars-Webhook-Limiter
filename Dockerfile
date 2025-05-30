FROM python:3.12-alpine

WORKDIR /app

COPY *.py .
COPY requirements.txt .

ENV TERM=xterm
ENV PYTHONUNBUFFERED=1

ARG TARGETPLATFORM
ARG BUILD_DATE
ARG COMMIT

RUN apk add --no-cache --virtual .build-deps build-base linux-headers libffi-dev openssl-dev && \
    apk add curl && \
    python -m pip install --upgrade pip && \
    pip install --upgrade setuptools && \
    pip install gunicorn && \
    pip install -r requirements.txt && \
    apk del .build-deps

EXPOSE 5000

LABEL maintainer="Discord: pika.pika.no.mi (970119359840284743)"
LABEL commit=$COMMIT
LABEL description="Listens for GitHub star events, notifies Discord on first-time stars, with SQLite & Sentry support."
LABEL release=$BUILD_DATE
LABEL VERSION="1.0.0"
LABEL url="https://github.com/Serpensin/GitHub-Stars-Webhook-Limiter"

CMD ["gunicorn", "-w", "4", "main:app", "-b", ":5000"]