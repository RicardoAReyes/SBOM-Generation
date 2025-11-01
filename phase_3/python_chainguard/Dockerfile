# Base stage: everything that should be cached
# This layer includes all tools and dependencies that rarely change
FROM cgr.dev/chainguard-private/python:3.11-dev AS base

USER root

RUN apk add --no-cache curl jq unzip git cosign

# Download and install chainver
RUN LATEST_URL=$(curl -s https://dl.enforce.dev/chainver/latest/latest-metadata.json | jq -r '.download_url') && \
    curl -LO "${LATEST_URL}" && \
    unzip chainver-*.zip && \
    cd chainver-package/archives && \
    ARCH=$(uname -m | sed 's/aarch64/arm64/; s/x86_64/x86_64/') && \
    tar -xzf chainver_*_Linux_${ARCH}.tar.gz && \
    chmod +x chainver && \
    mv chainver /usr/local/bin/ && \
    cd ../.. && \
    rm -rf chainver-*.zip chainver-package

# Download and install chainctl
RUN curl -o /usr/local/bin/chainctl "https://dl.enforce.dev/chainctl/latest/chainctl_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/aarch64/arm64/')" && \
    chmod +x /usr/local/bin/chainctl

# Final stage: application-specific parts that change frequently
FROM base AS final

WORKDIR /app

# Build args for Nexus configuration
# Default uses host.docker.internal for macOS/Windows Docker Desktop
# For Linux, use --build-arg NEXUS_HOST=<host-ip> when building
ARG NEXUS_HOST=host.docker.internal
ARG NEXUS_REPO=python-all

# Set index URL using ARG expansion
ARG PIP_INDEX_URL=http://${NEXUS_HOST}:8081/repository/${NEXUS_REPO}/simple/
ENV PIP_INDEX_URL=${PIP_INDEX_URL}

# Create directory for wheel files
RUN mkdir -p /app/wheels

# Copy dependency file first for better caching
COPY requirements.txt ./

# Copy .netrc for Nexus authentication (needed for pip to authenticate)
COPY .netrc /root/.netrc
RUN chmod 600 /root/.netrc

# Add a build arg to bust cache for pip download
# Pass --build-arg CACHE_BUST=$(date +%Y%m%d%H%M%S) to force fresh download
ARG CACHE_BUST

# Install dependencies using pip, downloading wheels to /app/wheels
# --trusted-host: Allow HTTP connections to Nexus
# --download: Download packages into target directory without installing
# Then install from the downloaded wheels (allowing PyPI for build deps only)
RUN pip download --trusted-host ${NEXUS_HOST} --dest /app/wheels -r requirements.txt && \
    pip install --find-links /app/wheels --trusted-host ${NEXUS_HOST} -r requirements.txt

# Download wheels directly from Chainguard Libraries for chainver verification
# These wheels will have Cosign signatures intact for verification
# Extract credentials from .netrc and use them directly
RUN NETRC_LOGIN=$(grep -A 2 'libraries.cgr.dev' /root/.netrc | grep 'login' | awk '{print $2}') && \
    NETRC_PASSWORD=$(grep -A 2 'libraries.cgr.dev' /root/.netrc | grep 'password' | awk '{print $2}') && \
    pip download --index-url "https://${NETRC_LOGIN}:${NETRC_PASSWORD}@libraries.cgr.dev/python/simple/" \
        --dest /app/wheels -r requirements.txt 2>&1 || \
    echo "Note: Direct download from Chainguard may have failed - chainver verification may be limited"

# Switch back to nonroot user for runtime
USER nonroot

# Copy application code
COPY --chown=nonroot:nonroot app.py ./

# Copy static files directory
COPY --chown=nonroot:nonroot static ./static

# Copy secrets.txt for CVE demonstration
COPY --chown=nonroot:nonroot secrets.txt ./secrets.txt

# Copy .netrc for Libraries API authentication (to current working directory /app)
COPY --chown=nonroot:nonroot .netrc ./.netrc

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV CHAINVER_PARENT_ORG=cameronmartin.dev

# Expose application port
EXPOSE 5000

# Run the aiohttp application using system python
ENTRYPOINT ["/usr/bin/python"]
CMD ["-u", "app.py"]

# Run the application
#CMD [ "python", "manage.py", "runserver", "0.0.0.0:8080" ]
