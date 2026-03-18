# MacroHard - Security Analysis Platform
# Production Docker Image with Real Analysis Capabilities

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=wsgi.py \
    FLASK_ENV=production \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    libpq-dev \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep (for security analysis)
RUN curl -L "https://github.com/returntocorp/semgrep/releases/latest/download/semgrep-linux-x86_64" -o /usr/local/bin/semgrep \
    && chmod +x /usr/local/bin/semgrep

# Create non-root user for security
RUN groupadd -r macrohard && useradd -r -g macrohard macrohard

# Set work directory
WORKDIR /app

# Install Python dependencies first (for better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Bandit for Python security analysis
RUN pip install --no-cache-dir bandit==1.7.7

# Copy application code
COPY . .

# Create data directory and temp directory and set permissions
RUN mkdir -p /app/instance && \
    mkdir -p /tmp/macrohard && \
    chown -R macrohard:macrohard /app/instance /tmp/macrohard

# Switch to non-root user
USER macrohard

# Expose port
EXPOSE 5001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')" || exit 1

# Run with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "4", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "wsgi:app"]
