# =============================================================================
# Stage 1 — Builder
# =============================================================================
FROM alpine:3.20 AS builder

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

RUN apk add --no-cache \
    bash \
    curl \
    wget \
    git \
    ca-certificates \
    python3 \
    py3-pip \
    build-base \
    python3-dev \
    libffi-dev

# Python venv
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade \
    semgrep \
    bandit \
    njsscan \
    jinja2 && \
    find /opt/venv -type d -name "__pycache__" -exec rm -rf {} + && \
    rm -rf /root/.cache/pip

WORKDIR /tools
ARG TRIVY_VERSION=0.69.3
ARG GITLEAKS_VERSION=8.30.0
ARG GOSEC_VERSION=2.24.7
ARG HADOLINT_VERSION=2.14.0

# Download scaners
RUN curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | tar -xz trivy && \
    curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz gitleaks && \
    curl -sfL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_amd64.tar.gz" | tar -xz gosec && \
    curl -sfL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64" -o hadolint && \
    chmod +x trivy gitleaks gosec hadolint && \
    curl -sfLo trivy-html.tpl https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/html.tpl

# =============================================================================
# Stage 2 — Runtime
# =============================================================================
FROM alpine:3.20

RUN apk add --no-cache \
    ca-certificates \
    git \
    bash \
    jq \
    python3 \
    curl \
    libgcc \
    libstdc++ && \
    addgroup -g 10001 scanner && \
    adduser -u 10001 -G scanner -D -H scanner && \
    mkdir -p /scanner/reports /scanner/templates /tmp/trivy-cache /tmp/semgrep-cache /home/scanner && \
    chown -R scanner:scanner /scanner /tmp /home/scanner

WORKDIR /scanner

COPY --from=builder --chown=scanner:scanner /opt/venv /opt/venv
COPY --from=builder --chown=scanner:scanner /tools/trivy /tools/gitleaks /tools/gosec /tools/hadolint /usr/local/bin/
COPY --from=builder --chown=scanner:scanner /tools/trivy-html.tpl /scanner/templates/

# scripts
COPY --chown=scanner:scanner generate_report.py entrypoint.sh /scanner/
RUN chmod +x /scanner/entrypoint.sh /scanner/generate_report.py

ENV PATH="/opt/venv/bin:/usr/local/bin:$PATH" \
    VIRTUAL_ENV=/opt/venv \
    PYTHONUNBUFFERED=1 \
    TRIVY_CACHE_DIR=/tmp/trivy-cache \
    SEMGREP_CACHE_DIR=/tmp/semgrep-cache \
    SEMGREP_SKIP_UNKNOWN_EXTENSIONS=true \
    SEMGREP_SEND_METRICS=off

USER 10001

ENTRYPOINT ["/scanner/entrypoint.sh"]
