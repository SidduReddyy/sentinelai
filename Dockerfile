FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY data/ ./data/

# Create non-root user
RUN useradd -m -u 1001 sentinelai && chown -R sentinelai:sentinelai /app
USER sentinelai

EXPOSE 8000

# Default: run the API server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
