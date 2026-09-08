FROM python:3.12-slim

WORKDIR /app

# System deps for cryptography and beautifulsoup
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install chromium + required linux dependencie
RUN python -m playwright install --with-deps chromium

COPY . .

# DB and certs will live in a volume
VOLUME ["/app/data"]

ENV DB_PATH=/app/data/scanner.db
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "app.py"]
