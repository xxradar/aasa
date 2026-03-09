"""Prompts for extracting regex rules from LLM judge findings."""

RULE_EXTRACTION_SYSTEM_PROMPT = """\
You are an expert regex engineer specializing in security pattern extraction.
Your job: given security findings from an AI analysis, determine which ones can
be expressed as regex rules and produce those regexes.

## Guidelines

A finding IS extractable if:
- The malicious content follows a consistent textual pattern (keywords, phrases, syntax)
- The pattern has recognizable structure (e.g., "ignore previous instructions" variants)
- A regex can catch the core pattern and reasonable synonyms/variations
- The pattern is language-based, not behavior-based

A finding is NOT extractable if:
- It relies on semantic understanding or contextual interpretation
- It requires understanding document structure beyond text matching
- It describes behavioral patterns (timing, side-channels, multi-step)
- The "attack" is purely about the placement/context, not the text itself
- It would require NLP-level understanding to detect

## Regex Quality Standards
- Use Python regex syntax (re module)
- Case-insensitive matching assumed (re.IGNORECASE)
- Prefer \\b word boundaries to reduce false positives
- Use non-greedy quantifiers where appropriate
- Use alternation (|) to cover synonyms and variations
- Keep patterns readable — no overly clever constructs
- Max ~200 chars per pattern — if longer, it's probably too specific
"""

BATCH_RULE_EXTRACTION_PROMPT = """\
Analyze the following {count} security findings from an LLM judge scan.
For each finding, determine if it can be expressed as a regex rule.

FINDINGS:
{findings_block}

Respond with a JSON array. For each finding (in order), return:
{{
  "finding_index": 0,
  "extractable": true/false,
  "regex_pattern": "...",
  "explanation": "why this works or why it cannot be a regex",
  "test_cases": [
    {{"text": "sample text that SHOULD match", "should_match": true}},
    {{"text": "sample text that should NOT match", "should_match": false}}
  ],
  "confidence": 0.0-1.0
}}

Rules:
- Only set extractable=true if you are confident the regex will work reliably
- Provide at least 1 positive and 1 negative test case for extractable rules
- Set confidence based on how well the regex generalizes (1.0 = perfect, 0.5 = risky)
- If the evidence is too short or generic, set extractable=false
- Omit regex_pattern and test_cases if extractable=false

Respond ONLY with the JSON array, no markdown fences or commentary.
"""
