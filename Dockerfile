FROM python:3.12-slim

LABEL maintainer="AASA — AI Agent Attack Surface Analyzer"
LABEL description="Scan websites for indirect prompt injection and AI agent attack surface vulnerabilities"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create results dir and non-root user
RUN mkdir -p /app/results && \
    useradd -m -r aasa && \
    chown -R aasa:aasa /app
USER aasa

EXPOSE 6001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:6001/api/v1/health || exit 1

# Default: run the web server
# Override with: docker run aasa python cli.py https://example.com
ENTRYPOINT ["python"]
CMD ["main.py"]
