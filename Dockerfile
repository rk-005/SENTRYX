FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY models.py .
COPY detectors.py .
COPY context_analyzer.py .
COPY reward_engine.py .
COPY tasks.py .
COPY env.py .
COPY server.py .
COPY inference.py .
COPY openenv.yaml .
COPY README.md .

# Expose the port HF Spaces expects
EXPOSE 7860

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:7860/')" || exit 1

# Run the server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "7860"]
