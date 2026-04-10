FROM python:3.11-slim

LABEL maintainer="security-team"
LABEL description="Security Middleware Pipeline — Wazuh/DefectDojo → Redmine"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ src/
COPY web/ web/
COPY config/ config/

# Create data directory for SQLite dedup database
RUN mkdir -p /app/data

# Default command: run the pipeline
ENTRYPOINT ["python", "-m", "src.main"]
CMD []
