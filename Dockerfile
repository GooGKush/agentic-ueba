FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    SKILLS_ROOT=/app/skills

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ ./src/

# Install canonical skills directly into /app/skills
RUN mkdir -p /app/skills && \
    git clone --depth 1 https://github.com/GooGKush/secops-risk-metrics-multistage.git /app/skills/secops-risk-metrics-multistage && \
    git clone --depth 1 https://github.com/GooGKush/secops-statistical-hunter.git /app/skills/secops-statistical-hunter && \
    rm -rf /app/skills/*/.git

EXPOSE 8080

CMD ["sh", "-c", "exec uvicorn src.server:app --host 0.0.0.0 --port ${PORT:-8080}"]
