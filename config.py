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

    model_config = {"env_prefix": "AASA_", "env_file": ".env"}


settings = Settings()
