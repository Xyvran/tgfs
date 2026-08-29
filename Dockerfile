FROM python:3.13-slim AS builder

WORKDIR /app

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN pip install poetry

# Copy poetry files
COPY pyproject.toml poetry.lock ./

# Configure poetry to install in system
RUN poetry config virtualenvs.create false

# Install dependencies
RUN poetry install --only=main --no-root

# Final stage
FROM python:3.13-slim

WORKDIR /app

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder stage
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY tgfs/ ./tgfs/
COPY asgidav/ ./asgidav/
COPY main.py ./

# Create non-root user
RUN useradd --create-home --shell /bin/bash tgfs
USER tgfs

# HTTP (WebDAV + manager API)
EXPOSE 1900
# SFTP, when tgfs.sftp.enabled is set in the config
EXPOSE 2222

# The application reads TGFS_DATA_DIR. Pin it so the data directory does not
# depend on HOME or on the passwd entry of whatever user the container runs as
# -- without it, `--user <uid with no passwd entry>` makes Python's expanduser
# return "~/.tgfs" literally and the config is looked for under /app/~/.tgfs.
ENV TGFS_DATA_DIR=/home/tgfs/.tgfs

# Run the application
CMD ["python", "main.py"]