# Stage 1: Build & Dependencies
# Pinned version by SHA to prevent upstream injection vulnerabilities
FROM alpine:3.20.2@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5 AS builder

RUN apk add --no-cache python3 py3-pip git build-base python3-dev

WORKDIR /app
COPY requirements.txt .
# Install packages securely into a virtual environment
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Stage 2: Hardened Runtime Environment
FROM alpine:3.20.2@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5

# Install lightweight runtime requirements
RUN apk add --no-cache python3 py3-pip && \
    addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy python virtual environment and code logic
COPY --from=builder /opt/venv /opt/venv
COPY entrypoint.py /app/entrypoint.py

# Restrict runtime environment execution permissions
WORKDIR /app
ENV PATH="/opt/venv/bin:$PATH"
USER appuser

ENTRYPOINT ["python3", "/app/entrypoint.py"]
