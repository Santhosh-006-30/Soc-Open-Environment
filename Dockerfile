FROM python:3.10.13-slim

WORKDIR /app

# Install dependencies with retries for network resilience
COPY requirements.txt .
RUN pip install --no-cache-dir --retries 5 -r requirements.txt

# Copy project files
COPY . .

# Expose HuggingFace Spaces default port
EXPOSE 7860

# Health check - simple port check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=10s \
  CMD python -c "import socket; socket.create_connection(('localhost', 7860), timeout=5)" || exit 1

# Start the FastAPI server
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]
