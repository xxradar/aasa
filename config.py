"""Configuration for AI Agent Attack Surface Analyzer."""

import os
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # API
    app_name: str = "AI Agent Attack Surface Analyzer"
    app_version: str = "0.1.0"
    host: str = "0.0.0.0"
    port: int = 6001
    debug: bool = False

    # Crawler
    max_depth: int = 2
    max_pages: int = 50
    request_timeout: int = 15
    user_agent: str = "AASA-Scanner/0.1 (AI Agent Attack Surface Analyzer)"
    respect_robots_txt: bool = True
    concurrent_requests: int = 5

    # Agentic file targets
    agentic_files: list[str] = [
        "Claude.md", "CLAUDE.md", "claude.md",
        "Agents.md", "AGENTS.md", "agents.md",
        ".well-known/ai-plugin.json",
        ".well-known/agent.json",
        "llms.txt", "llms-full.txt",
        ".github/copilot-instructions.md",
        ".cursorrules", ".cursorignore",
        "CONTEXT.md", "AI.md",
        "system_prompt.txt", "system-prompt.md",
    ]

    # Well-known API documentation / spec endpoints (probed during website scan)
    api_discovery_paths: list[str] = [
        # OpenAPI / Swagger
        "openapi.json", "openapi.yaml", "openapi.yml",
        "swagger.json", "swagger.yaml", "swagger.yml",
        "api-docs", "api-docs.json",
        "docs", "docs/openapi.json",
        "redoc",
        "swagger-ui", "swagger-ui/index.html", "swagger-ui.html",
        "v1/openapi.json", "v2/openapi.json", "v3/openapi.json",
        "api/openapi.json", "api/swagger.json",
        "api/v1/openapi.json", "api/v1/swagger.json",
        "api/v2/openapi.json", "api/v2/swagger.json",
        ".well-known/openapi.yaml",
        # GraphQL
        "graphql", "graphiql", "playground",
        "api/graphql", "v1/graphql",
        # Generic API paths
        "api", "api/", "api/v1", "api/v2", "api/v3",
        "api/v1/", "api/v2/", "api/v3/",
        # Health / status / metadata
        "api/health", "api/v1/health",
        "health", "healthz", "readyz",
        "status", "api/status",
        "_health", "_status",
        # Other specs
        "api/schema", "schema", "schema.json",
        "api-spec", "api-spec.json",
        "wadl", "api.wadl",
        # Admin / debug endpoints
        "admin", "admin/", "_admin",
        "debug", "debug/", "_debug",
        "metrics", "prometheus/metrics",
        "actuator", "actuator/health", "actuator/info", "actuator/env",
        # gRPC
        "grpc/reflection",
        # Websocket
        "ws", "websocket", "api/ws",
    ]

    # LLM Judge
    anthropic_api_key: Optional[str] = None
    llm_model: str = "claude-sonnet-4-5-20250929"
    llm_judge_enabled: bool = True
    llm_max_tokens: int = 4096

    # Scoring
    severity_weights: dict = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1,
    }

    # Rule Learning
    rule_learning_enabled: bool = True
    rule_auto_promote_threshold: int = 0  # 0 = manual only, N = auto after N confirmations
    rule_min_confidence: float = 0.7
    rules_dir: str = "/app/results"  # Where learned_rules.json lives

    # Authentication
    auth_enabled: bool = True
    secret_key: str = "change-me-in-production-use-a-real-secret"  # JWT + session signing
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 1440  # 24 hours

    # OAuth providers (set via env vars AASA_GITHUB_CLIENT_ID etc.)
    github_client_id: Optional[str] = None
    github_client_secret: Optional[str] = None
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None

    # SQLite user database path
    auth_db_path: str = "/app/results/users.db"

    model_config = {"env_prefix": "AASA_", "env_file": ".env"}


settings = Settings()
