FROM python:3.11-slim

LABEL maintainer="security-team"
LABEL description="Security Middleware — Wazuh/DefectDojo → Redmine"

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .
COPY app/ app/
COPY frontend/ frontend/
COPY config/ config/

# Create data directories for logs, local DB fallback, and backups
RUN mkdir -p /app/data/db /app/data/logs /app/data/backups

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/pipeline/status')" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
