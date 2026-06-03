import os
import json
import re
import logging
import google.generativeai as genai
import google.api_core.exceptions

logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
genai.configure(api_key=GEMINI_API_KEY)
_model = genai.GenerativeModel('gemini-2.0-flash')

_SYSTEM_PROMPT = """You are an expert Solidity smart contract security auditor.

Analyze the provided Solidity source code for security vulnerabilities.

You MUST return a JSON object ONLY — no markdown, no explanation, no code fences.
Return exactly this structure with no extra keys:

{
  "contract": "<filename>",
  "timestamp": "<ISO 8601 UTC datetime>",
  "vulnerabilities": [
    {
      "type": "<vulnerability type name>",
      "line": <integer line number or null if unknown>,
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "details": "<clear explanation of the issue and how to fix it>"
    }
  ],
  "severity": "<CRITICAL|HIGH|MEDIUM|LOW|SAFE>",
  "verdict": "<SAFE|UNSAFE>"
}

Severity rules:
- CRITICAL: funds can be directly drained (reentrancy, arbitrary external calls, missing auth on withdraw)
- HIGH: significant risk (access control bypass, integer overflow, selfdestruct misuse)
- MEDIUM: meaningful risk (unchecked return values, tx.origin auth, timestamp dependence)
- LOW: minor risk (gas inefficiency, non-critical best practice violations)
- SAFE: no significant vulnerabilities found

Rules:
- overall severity = highest individual finding severity
- if vulnerabilities array is empty: severity = "SAFE", verdict = "SAFE"
- if any vulnerabilities found: verdict = "UNSAFE"

Check for at minimum:
1. Reentrancy (external call before state update — CEI pattern violations)
2. Integer overflow / underflow (without SafeMath or unchecked blocks)
3. Access control issues (missing onlyOwner, public functions that should be restricted)
4. tx.origin authentication
5. Unchecked external call return values
6. Selfdestruct misuse
7. Delegatecall risks (storage layout mismatch)
8. Front-running / MEV vulnerabilities
9. Timestamp dependence (block.timestamp for critical logic)
10. Unprotected ETH withdrawal"""


def _parse_response(raw_text: str) -> dict:
    """
    Parse Gemini response text into dict.
    Strips markdown code fences if present.
    """
    clean = re.sub(r'```(?:json)?\s*', '', raw_text).strip().rstrip('`').strip()
    return json.loads(clean)


def analyze(source_code: str, filename: str) -> dict:
    """
    Analyze Solidity source code using Gemini 1.5 Flash.
    Returns report dict.
    Raises google.api_core.exceptions.ResourceExhausted on quota (HTTP 429).
    Raises Exception on other failures.
    """
    user_prompt  = f"Filename: {filename}\n\nSource code:\n{source_code}"
    full_prompt  = f"{_SYSTEM_PROMPT}\n\n{user_prompt}"

    response = _model.generate_content(full_prompt)
    raw_text = response.text

    result = _parse_response(raw_text)
    result['analysis_type'] = 'ai'

    logger.info(
        f"Gemini analysis complete | contract={filename} | "
        f"severity={result.get('severity')} | "
        f"findings={len(result.get('vulnerabilities', []))}"
    )
    return result
