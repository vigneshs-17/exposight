# ==============================================================================
# Stage 1: Builder
# Pinned to specific patch version and Debian codename (3.12.14-slim-trixie)
# for reproducibility, and kept current by Dependabot.
# ==============================================================================
FROM python:3.12.14-slim-trixie AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src/ ./src/

# Build standard wheel artifact containing only production dependencies
RUN pip install --no-cache-dir --upgrade pip build \
    && python -m build --wheel --outdir /wheels

# ==============================================================================
# Stage 2: Runtime
# Uses the exact same pinned base image to ensure ABI/glibc compatibility while
# discarding all build compilers and development tools.
# ==============================================================================
FROM python:3.12.14-slim-trixie AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Apply Debian security updates published after the base image was built (Phase G, D18):
# the trivy gate fails on fixable HIGH/CRITICAL OS packages, and the pinned base tag can
# lag behind them. Image contents therefore depend on the build date.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root system user "asm" (UID/GID 10001) and pre-create /app/output
RUN groupadd -r -g 10001 asm \
    && useradd -r -g asm -u 10001 -d /app -s /bin/false asm \
    && mkdir -p /app/output \
    && chown -R asm:asm /app

WORKDIR /app

# Copy wheel artifact from builder stage and install runtime dependencies
COPY --from=builder /wheels /wheels
# pip is removed afterwards (Phase G, D23): nothing at runtime installs packages, and its
# known CVEs then cannot apply to the image.
RUN pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels \
    && python -m pip uninstall -y pip

# Copy migrations and alembic configuration for container migrations
COPY --chown=asm:asm alembic.ini ./
COPY --chown=asm:asm migrations/ ./migrations/

# Drop root privileges
USER asm

ENTRYPOINT ["asm"]
CMD ["--help"]
