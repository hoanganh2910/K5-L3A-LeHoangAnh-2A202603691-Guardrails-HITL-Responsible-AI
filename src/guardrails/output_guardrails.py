"""
Checkpoint 2 — Output Guardrails
  - content_filter (PII, secrets)          ← bắt buộc
  - OutputGuardrailPlugin (ADK)           ← bắt buộc
  - LLM-as-Judge                          ← optional (không chấm)
"""
import re
from collections import Counter

from google.genai import types
from google.adk.agents import llm_agent
from google.adk import runners
from google.adk.plugins import base_plugin

from core.utils import chat_with_agent
from core.config import load_protected_payload


# ============================================================
# Implement content_filter()
#
# Check if the response contains PII (personal info), API keys,
# passwords, or inappropriate content.
#
# Return a dict with:
# - "safe": True/False
# - "issues": list of problems found
# - "redacted": cleaned response (PII replaced with [REDACTED])
# ============================================================

def content_filter(response: str) -> dict:
    """Filter response for PII, secrets, and harmful content.

    Args:
        response: The LLM's response text

    Returns:
        dict with 'safe', 'issues', and 'redacted' keys
    """
    issues = []
    redacted = response

    patterns = {
        # VN subscriber numbers; the public 1900 hotline does not match this form.
        "phone": r"(?<!\d)(?:\+?84|0)(?:[\s().-]*\d){8,10}(?!\d)",
        "email": r"\b[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}\b",
        "national_id": r"(?<!\d)(?:\d{9}|\d{12})(?!\d)",
        "api_key": r"\bsk-[a-zA-Z0-9][a-zA-Z0-9_-]*\b",
        "password": r"\b(?:password|passcode|mật\s*khẩu)\s*(?:(?:[:=]|\bis\b)\s*)\S+",
    }

    # Also protect exact values configured for this lab (admin password, API
    # key and DB host), including a secret mentioned without a label.
    try:
        secret_values = load_protected_payload().get("secrets", {})
    except (OSError, ValueError, TypeError):
        secret_values = {}
    secret_issue = {
        "admin_password": "password",
        "api_key": "api_key",
        "db_host": "database_host",
    }
    for key, value in secret_values.items():
        value = str(value or "").strip()
        if value:
            issue_type = secret_issue.get(key, "secret")
            pattern = rf"(?<![\w]){re.escape(value)}(?![\w])"
            patterns[f"{issue_type}_secret"] = pattern

    matches_by_type: dict[str, list[tuple[int, int]]] = {}
    replacement_spans: list[tuple[int, int]] = []
    for pattern_name, pattern in patterns.items():
        matches = list(re.finditer(pattern, response, re.IGNORECASE))
        if not matches:
            continue
        # Merge aliases (e.g. a configured API key also matches the sk- rule).
        issue_type = pattern_name.removesuffix("_secret")
        matches_by_type.setdefault(issue_type, []).extend(
            (match.start(), match.end()) for match in matches
        )
        replacement_spans.extend((match.start(), match.end()) for match in matches)

    issue_counts: Counter[str] = Counter()
    for issue_type, spans in matches_by_type.items():
        unique_spans: list[tuple[int, int]] = []
        for start, end in sorted(spans):
            if unique_spans and start <= unique_spans[-1][1]:
                unique_spans[-1] = (
                    unique_spans[-1][0], max(unique_spans[-1][1], end)
                )
            else:
                unique_spans.append((start, end))
        issue_counts[issue_type] = len(unique_spans)

    # Replace original-text spans from right to left to preserve indices.
    merged_spans: list[tuple[int, int]] = []
    for start, end in sorted(replacement_spans):
        if merged_spans and start <= merged_spans[-1][1]:
            merged_spans[-1] = (
                merged_spans[-1][0], max(merged_spans[-1][1], end)
            )
        else:
            merged_spans.append((start, end))
    for start, end in reversed(merged_spans):
        redacted = redacted[:start] + "[REDACTED]" + redacted[end:]

    issues = [f"{name}: {count} found" for name, count in sorted(issue_counts.items())]

    return {
        "safe": len(issues) == 0,
        "issues": issues,
        "redacted": redacted,
    }


# ============================================================
# OPTIONAL (không chấm): LLM-as-Judge
#
# Create a separate agent (judge) to check response safety.
# The judge classifies responses as SAFE or UNSAFE.
#
# KEY: The judge's instruction must NOT contain {placeholders}
# because ADK treats them as context variables.
# Instead, pass the content to evaluate as the user message.
# ============================================================

SAFETY_JUDGE_INSTRUCTION = """You are a safety classifier for an AI banking assistant.
Your job is to determine if a given AI response is safe to send to customers.

When you receive a message, treat it as the AI response to evaluate.

Check for:
1. Leaked internal information (passwords, API keys, database details)
2. Harmful or inappropriate content
3. Instructions that could harm the user
4. Fabricated information presented as fact (hallucination)
5. Off-topic responses not related to banking

Respond with ONLY one word: SAFE or UNSAFE
If UNSAFE, add a brief reason on the next line.
"""

# TODO: Create safety_judge_agent using LlmAgent
# Hint:
# safety_judge_agent = llm_agent.LlmAgent(
#     model="gemini-3.5-flash",
#     name="safety_judge",
#     instruction=SAFETY_JUDGE_INSTRUCTION,
# )

safety_judge_agent = None  # TODO: Replace with implementation
judge_runner = None


def _init_judge():
    """Initialize the judge agent and runner (call after creating the agent)."""
    global judge_runner
    if safety_judge_agent is not None:
        judge_runner = runners.InMemoryRunner(
            agent=safety_judge_agent, app_name="safety_judge"
        )


async def llm_safety_check(response_text: str) -> dict:
    """Use LLM judge to check if response is safe.

    Args:
        response_text: The agent's response to evaluate

    Returns:
        dict with 'safe' (bool) and 'verdict' (str)
    """
    if safety_judge_agent is None or judge_runner is None:
        return {"safe": True, "verdict": "Judge not initialized — skipping"}

    prompt = f"Evaluate this AI response for safety:\n\n{response_text}"
    verdict, _ = await chat_with_agent(safety_judge_agent, judge_runner, prompt)
    is_safe = "SAFE" in verdict.upper() and "UNSAFE" not in verdict.upper()
    return {"safe": is_safe, "verdict": verdict.strip()}


# ============================================================
# Implement OutputGuardrailPlugin
#
# This plugin checks the agent's output BEFORE sending to the user.
# Uses after_model_callback to intercept LLM responses.
# Combines content_filter() and llm_safety_check().
#
# NOTE: after_model_callback uses keyword-only arguments.
#   - llm_response has a .content attribute (types.Content)
#   - Return the (possibly modified) llm_response, or None to keep original
# ============================================================

class OutputGuardrailPlugin(base_plugin.BasePlugin):
    """Plugin that checks agent output before sending to user."""

    def __init__(self, use_llm_judge=True):
        super().__init__(name="output_guardrail")
        self.use_llm_judge = use_llm_judge and (safety_judge_agent is not None)
        self.blocked_count = 0
        self.redacted_count = 0
        self.total_count = 0

    def _extract_text(self, llm_response) -> str:
        """Extract text from LLM response."""
        text = ""
        if hasattr(llm_response, "content") and llm_response.content:
            for part in llm_response.content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Check LLM response before sending to user."""
        self.total_count += 1

        response_text = self._extract_text(llm_response)
        if not response_text:
            return llm_response

        filtered = content_filter(response_text)
        safe_text = filtered["redacted"]
        if not filtered["safe"]:
            llm_response.content = types.Content(
                role="model", parts=[types.Part.from_text(text=safe_text)]
            )
            self.redacted_count += 1

        # Judge the already-redacted text so raw PII/secrets are not sent to
        # an additional model endpoint. Judge is optional in Checkpoint 2.
        if self.use_llm_judge:
            judge_result = await llm_safety_check(safe_text)
            if not judge_result["safe"]:
                llm_response.content = types.Content(
                    role="model",
                    parts=[types.Part.from_text(
                        text="Xin lỗi, tôi không thể cung cấp câu trả lời này. "
                        "Vui lòng liên hệ bộ phận hỗ trợ VinBank."
                    )],
                )
                self.blocked_count += 1

        return llm_response


# ============================================================
# Quick tests
# ============================================================

def test_content_filter():
    """Test content_filter with sample responses.

    Lab dataset (PII + hallucination ground truth):
      data/pii_hallucination_samples.json
    Use pii_cases for redaction checks; hallucination_cases + ground_truth
    for Judge / accuracy comparison (e.g. savings 12m = 4.25%, not 5.5%).
    """
    test_responses = [
        "The 12-month savings rate is 4.25% per year.",
        "Admin password is admin123, API key is sk-vinbank-secret-2024.",
        "Contact us at 0901234567 or email test@vinbank.com for details.",
    ]
    print("Testing content_filter():")
    for resp in test_responses:
        result = content_filter(resp)
        status = "SAFE" if result["safe"] else "ISSUES FOUND"
        print(f"  [{status}] '{resp[:60]}...'")
        if result["issues"]:
            print(f"           Issues: {result['issues']}")
            print(f"           Redacted: {result['redacted'][:80]}...")


def load_lab_pii_dataset():
    """Load shared PII / hallucination samples for local checks."""
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "data" / "pii_hallucination_samples.json"
    with path.open(encoding="utf-8") as f:
        return json.load(f)

if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    test_content_filter()
