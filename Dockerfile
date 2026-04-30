# SecOps Tool - Security Scanner
# Multi-stage build with all security tools pre-installed

FROM python:3.11-slim AS base

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Go for gosec and gitleaks
RUN wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz \
    && rm go1.21.6.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:$PATH"
ENV GOPATH="/root/go"
ENV PATH="$GOPATH/bin:$PATH"

# Install security tools
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest \
    && go install github.com/zricethezav/gitleaks/v8@latest \
    && go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Install semgrep
RUN pip install --no-cache-dir semgrep

# Install cdxgen for SBOM generation
RUN npm install -g @cyclonedx/cdxgen

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
