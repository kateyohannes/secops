# Multi-stage Dockerfile for SecOps Tool
# Stage 1: Build Go tools
FROM golang:1.21-alpine AS go-builder

RUN go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install github.com/zricethezav/gitleaks/v8@latest && \
    go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Stage 2: Build Python base with semgrep
FROM python:3.11-slim AS python-base

RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install semgrep
RUN pip install --no-cache-dir semgrep

# Stage 3: Final image
FROM python:3.11-slim

# Copy Go binaries from builder
COPY --from=go-builder /root/go/bin/gosec /usr/local/bin/
COPY --from=go-builder /root/go/bin/gitleaks /usr/local/bin/
COPY --from=go-builder /root/go/bin/osv-scanner /usr/local/bin/

# Copy Python and semgrep from python-base
COPY --from=python-base /usr/local/bin/semgrep /usr/local/bin/
COPY --from=python-base /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Install Node.js and cdxgen
RUN apt-get update && apt-get install -y \
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g @cyclonedx/cdxgen \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the application
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Create a non-root user
RUN useradd -m -u 1000 secops && chown -R secops:secops /app
USER secops

ENTRYPOINT ["secops"]
CMD ["--help"]
