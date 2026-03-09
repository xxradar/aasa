from .base import BaseAnalyzer
from .hidden_text import HiddenTextAnalyzer
from .metadata import MetadataAnalyzer
from .tool_patterns import ToolPatternAnalyzer
from .prompt_injection import PromptInjectionAnalyzer
from .exfiltration import ExfiltrationAnalyzer
from .markdown_injection import MarkdownInjectionAnalyzer
from .pdf_analyzer import PDFAnalyzer
from .llm_judge import LLMJudgeAnalyzer
from .learned_rules import LearnedRuleAnalyzer

# Static rule-based analyzers (instantiated with no args)
ALL_STATIC_ANALYZERS: list[type[BaseAnalyzer]] = [
    HiddenTextAnalyzer,
    MetadataAnalyzer,
    ToolPatternAnalyzer,
    PromptInjectionAnalyzer,
    ExfiltrationAnalyzer,
    MarkdownInjectionAnalyzer,
]

# Note: LearnedRuleAnalyzer is NOT in ALL_STATIC_ANALYZERS because it
# requires a rules_file path at init time. Scanner constructs it separately.

__all__ = [
    "BaseAnalyzer",
    "HiddenTextAnalyzer",
    "MetadataAnalyzer",
    "ToolPatternAnalyzer",
    "PromptInjectionAnalyzer",
    "ExfiltrationAnalyzer",
    "MarkdownInjectionAnalyzer",
    "PDFAnalyzer",
    "LLMJudgeAnalyzer",
    "LearnedRuleAnalyzer",
    "ALL_STATIC_ANALYZERS",
]
