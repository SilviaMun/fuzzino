# Fuzzino

Analyzes static files from web applications to find security vulnerabilities, using deterministic detection + local LLM analysis via Ollama.

## Quick start

```bash
cp .env.example .env
pip install -r requirements.txt
ollama serve
python app.py
```

First launch creates the admin account. Add teammates from the Users tab.

## Docker

```bash
cp .env.example .env
# Edit .env: OLLAMA_HOST=http://host.docker.internal:11434
docker compose up -d
```

## CLI

```bash
# Local
python cli.py https://target.com

# Via relay
python cli.py https://target.com \
    --ollama http://192.168.1.50:8080/api/relay \
    -u admin -p secret

# With VPN, no crawl, SPA rendering
python cli.py https://target.com \
    --proxy socks5://10.0.0.1:1080 \
    --no-crawl --render \
    -o report.json --html report.html
```

## Disclaimer

This tool is intended exclusively for authorized penetration testing.