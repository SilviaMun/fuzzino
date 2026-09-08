"""
Configuration from environment variables / .env file.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Ollama
    ollama_host: str = Field(default="http://localhost:11434", description="Ollama API URL (internal, never exposed)")
    default_model: str = Field(default="qwen2.5-coder:32b", description="Default LLM model")

    # Server
    server_host: str = Field(default="0.0.0.0", description="Listen address")
    server_port: int = Field(default=8080, description="Listen port")

    # Security
    secret_key: str = Field(default="change-me-in-production-use-a-random-string", description="Session secret key")
    relay_rate_limit: int = Field(default=30, description="Max Ollama relay requests per minute per user")

    # Scanner defaults
    default_rate_limit: float = Field(default=0.1, description="Default seconds between target requests")
    max_file_size_mb: int = Field(default=2, description="Max file size to download (MB)")
    llm_timeout: int = Field(default=300, description="LLM request timeout in seconds")
    llm_temperature: float = Field(default=0.1, description="LLM temperature")
    llm_max_tokens: int = Field(default=4096, description="LLM max output tokens")

    # Crawler & renderer
    enable_crawl: bool = Field(default=True, description="Recursive crawling for additional pages")
    max_crawl_pages: int = Field(default=20, description="Max pages to crawl")
    enable_renderer: str = Field(default="auto", description="SPA rendering: 'auto' (detect), 'true' (always), 'false' (never)")

    # Session
    session_timeout_minutes: int = Field(default=60, description="Session inactivity timeout in minutes")

    # Notifications
    webhook_url: str = Field(default="", description="Webhook URL for scan completion notifications")
    slack_url: str = Field(default="", description="Slack incoming webhook URL")
    smtp_host: str = Field(default="", description="SMTP server for email notifications")
    smtp_port: int = Field(default=587, description="SMTP port")
    smtp_sender: str = Field(default="", description="SMTP sender email")
    smtp_password: str = Field(default="", description="SMTP password")
    smtp_recipient: str = Field(default="", description="Notification email recipient")

    # Request limits
    max_request_body_mb: int = Field(default=10, description="Max request body size in MB")

    # Database
    db_path: str = Field(default="scanner.db", description="SQLite database path")

    # TLS
    enable_tls: bool = Field(default=True, description="Enable HTTPS with self-signed cert")

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()