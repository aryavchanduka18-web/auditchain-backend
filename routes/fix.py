import logging
from flask import Blueprint, request, jsonify
from services import ai_service, fallback_service

logger = logging.getLogger(__name__)
fix_bp = Blueprint('fix', __name__)


@fix_bp.route('/audit/fix', methods=['POST'])
def generate_fix():
    """
    On-demand fix generation — called only when user clicks "Download Suggested Fix".
    Accepts JSON: { source_code: str, filename: str }
    Returns: { fixed_code: str, filename: str }
    """
    data = request.get_json(silent=True)
    if not data or 'source_code' not in data:
        return jsonify({"error": "source_code is required.", "code": "MISSING_SOURCE"}), 400

    source_code = data.get('source_code', '')
    filename    = data.get('filename', 'contract.sol')

    if len(source_code) > 500_000:
        return jsonify({"error": "Source code too large.", "code": "TOO_LARGE"}), 400

    if not source_code.strip():
        return jsonify({"error": "Source code is empty.", "code": "EMPTY_SOURCE"}), 400

    try:
        fixed_code = ai_service.generate_fix(source_code, filename)
    except Exception as e:
        logger.warning(f"Gemini fix failed ({type(e).__name__}) — rule-based fallback")
        # Use fallback: run analysis then apply rule-based fixes
        report     = fallback_service.analyze(source_code, filename)
        fixed_code = fallback_service._generate_fixed_code(source_code, report['vulnerabilities'])

    logger.info(f"Fix generated | contract={filename}")
    return jsonify({"fixed_code": fixed_code, "filename": filename}), 200
