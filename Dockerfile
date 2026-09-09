# ─────────────────────────────────────────────────────────────────────────────
# Jen - The Kea DHCP Management Console
# Dockerfile
# ─────────────────────────────────────────────────────────────────────────────
FROM ubuntu:24.04

LABEL maintainer="jen-dhcp"
LABEL description="Jen - The Kea DHCP Management Console"
LABEL version="5.8.3"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    mariadb-client-core \
    openssh-client \
    openssl \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies — pinned list lives in requirements.txt (the single
# source of truth, shared with install.sh and CI; never re-listed inline).
# Copied first so this layer caches independently of the app source.
COPY requirements.txt /opt/jen/requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir -r /opt/jen/requirements.txt

# Create app user matching bare metal setup
RUN groupadd -r www-data 2>/dev/null || true && \
    useradd -r -g www-data -s /sbin/nologin www-data 2>/dev/null || true

# Create directories
RUN mkdir -p /opt/jen/static/icons/brands \
             /opt/jen/static/icons/custom \
             /opt/jen/templates \
             /etc/jen/ssl /etc/jen/ssh /etc/jen/backups

# Copy application files
COPY run.py        /opt/jen/run.py
COPY jen/          /opt/jen/jen/
COPY templates/    /opt/jen/templates/
COPY static/       /opt/jen/static/

# Set permissions
RUN chown -R www-data:www-data /opt/jen /etc/jen

# Volumes — persist config, certs, SSH keys, backups, and custom icons
VOLUME ["/etc/jen", "/opt/jen/static/icons/custom"]

# Expose ports
EXPOSE 5050 8443

# Health check — tries HTTP first, falls back to HTTPS
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -sf http://localhost:5050/ || curl -skf https://localhost:8443/ || exit 1

USER www-data

CMD ["python3", "/opt/jen/run.py"]
