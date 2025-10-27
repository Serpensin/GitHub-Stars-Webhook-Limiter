# Builder stage
FROM python:3.14-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache build-base libffi-dev linux-headers openssl-dev

# Copy and install Python dependencies
COPY requirements.txt .
RUN python -m pip install --upgrade pip && \
    pip install --upgrade setuptools wheel && \
    pip install --prefix=/install --no-warn-script-location \
        -r requirements.txt \
        gunicorn gevent greenlet

# Final stage
FROM python:3.14-alpine

WORKDIR /app

# Copy application files
COPY *.py .
COPY .config/ ./.config/
COPY routes/ ./routes/
COPY templates/ ./templates/
COPY static/ ./static/
COPY CustomModules/ ./CustomModules/

# Copy License and README
COPY LICENSE.txt .
COPY README.md .

# Install only runtime dependencies
RUN apk add --no-cache curl libstdc++

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

ENV TERM=xterm
ENV PYTHONUNBUFFERED=1

ARG TARGETPLATFORM
ARG BUILD_DATE
ARG COMMIT

EXPOSE 5000

LABEL maintainer="Discord: pika.pika.no.mi (970119359840284743)"
LABEL commit=$COMMIT
LABEL description="Listens for GitHub star & watch events, notifies Discord on first-time interactions, with SQLite & Sentry support."
LABEL release=$BUILD_DATE
LABEL VERSION="2.0.0"
LABEL url="https://github.com/Serpensin/GitHub-Stars-Webhook-Limiter"

CMD ["gunicorn", "-c", ".config/gunicorn.conf.py", "main:app"]