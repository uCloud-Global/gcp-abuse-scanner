# ─── Stage 1: builder ────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN pip install --no-cache-dir hatchling

# Copy full source so hatchling can build the wheel
COPY pyproject.toml README.md LICENSE ./
COPY gcp_abuse_scanner/ ./gcp_abuse_scanner/

# Build wheel into /build/dist/
RUN pip wheel --no-cache-dir --wheel-dir /build/dist .

# ─── Stage 2: runtime ────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="gcp-abuse-scanner"
LABEL org.opencontainers.image.description="Preventive GCP security scanner for crypto mining and Gemini API abuse"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/uCloud-Global/gcp-abuse-scanner"
LABEL org.opencontainers.image.documentation="https://github.com/uCloud-Global/gcp-abuse-scanner/tree/main/docs"

# Security: non-root user
RUN groupadd -r scanner && useradd -r -g scanner scanner

WORKDIR /app

# Install the pre-built wheel (no build tools needed at runtime)
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Output directory for reports (writable by scanner user)
RUN mkdir -p /reports && chown scanner:scanner /reports

USER scanner

WORKDIR /reports

ENTRYPOINT ["gcp-abuse-scanner"]
CMD ["--help"]
