import re
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0}

PATTERNS = [
    {
        "type": "Reentrancy",
        "severity": "CRITICAL",
        "regex": re.compile(r'\.call\s*\{[^}]*value\s*:'),
        "details": (
            "External call with value transfer detected before state update — "
            "classic reentrancy vulnerability. Update state before making external calls (CEI pattern)."
        )
    },
    {
        "type": "tx.origin Authentication",
        "severity": "HIGH",
        "regex": re.compile(r'\btx\.origin\b'),
        "details": (
            "tx.origin used for authentication — vulnerable to phishing attacks. "
            "Use msg.sender instead of tx.origin for all authorization checks."
        )
    },
    {
        "type": "Unchecked External Call",
        "severity": "MEDIUM",
        "regex": re.compile(r'\b\w+\.call\s*\('),
        "details": (
            "External call return value may not be checked. "
            "Verify the bool return value or use a SafeCall pattern."
        )
    },
    {
        "type": "Selfdestruct",
        "severity": "HIGH",
        "regex": re.compile(r'\bselfdestruct\s*\('),
        "details": (
            "Contract can be permanently destroyed via selfdestruct. "
            "Ensure this function is access-controlled and truly intentional."
        )
    },
    {
        "type": "Delegatecall",
        "severity": "HIGH",
        "regex": re.compile(r'\bdelegatecall\s*\('),
        "details": (
            "Delegatecall detected — the called contract executes in this contract's storage context. "
            "Storage layout must exactly match the target contract."
        )
    },
]


def _generate_fixed_code(source_code: str, findings: list) -> str:
    """
    Apply basic inline fixes to the source code based on detected findings.
    Each fix is annotated with an AUDITCHAIN FIX comment.
    """
    import re as _re
    fixed = source_code

    for f in findings:
        if f['type'] == 'Reentrancy':
            # Wrap the vulnerable .call line with a comment
            fixed = _re.sub(
                r'([ \t]*)(.*\.call\s*\{[^}]*value[^}]*\}\s*\([^)]*\)\s*;)',
                r'\1// AUDITCHAIN FIX: Move state update (e.g. balances[msg.sender] = 0) ABOVE this line to follow the Checks-Effects-Interactions pattern\n\1\2',
                fixed,
                count=1
            )
        elif f['type'] == 'tx.origin Authentication':
            fixed = _re.sub(
                r'\btx\.origin\b',
                'msg.sender /* AUDITCHAIN FIX: tx.origin replaced with msg.sender to prevent phishing */',
                fixed,
                count=1
            )
        elif f['type'] == 'Selfdestruct':
            fixed = _re.sub(
                r'\bselfdestruct\s*\(',
                'selfdestruct( /* AUDITCHAIN FIX: Add onlyOwner or access control modifier to this function */',
                fixed,
                count=1
            )
        elif f['type'] == 'Delegatecall':
            fixed = _re.sub(
                r'\bdelegatecall\s*\(',
                'delegatecall( /* AUDITCHAIN FIX: Verify storage layout matches target contract exactly */',
                fixed,
                count=1
            )
        elif f['type'] == 'Unchecked External Call':
            fixed = _re.sub(
                r'(\b\w+\.call\s*\([^)]*\)\s*;)',
                r'(bool _success,) = \1\n        require(_success, "External call failed"); // AUDITCHAIN FIX: Check return value',
                fixed,
                count=1
            )

    return fixed


def analyze(source_code: str, filename: str) -> dict:
    """
    Run rule-based vulnerability analysis on Solidity source code.
    Returns a report dict matching the same schema as ai_service.analyze().
    """
    lines = source_code.split('\n')
    findings = []

    for pattern in PATTERNS:
        for line_num, line in enumerate(lines, start=1):
            if pattern["regex"].search(line):
                findings.append({
                    "type":     pattern["type"],
                    "line":     line_num,
                    "severity": pattern["severity"],
                    "details":  pattern["details"]
                })
                break  # one finding per pattern type

    if not findings:
        overall_severity = "SAFE"
        verdict = "SAFE"
    else:
        highest = max(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 0))
        overall_severity = highest["severity"]
        verdict = "UNSAFE"

    logger.info(f"Rule-based analysis complete | contract={filename} | severity={overall_severity}")

    fixed_code = _generate_fixed_code(source_code, findings) if findings else source_code

    return {
        "contract":        filename,
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "vulnerabilities": findings,
        "severity":        overall_severity,
        "verdict":         verdict,
        "analysis_type":   "rule_based",
        "fixed_code":      fixed_code
    }
