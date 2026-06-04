import json
import logging
from flask import Blueprint, request, Response, stream_with_context
from services import ai_service, fallback_service, ipfs_service, blockchain_service
from utils.validation import validate_sol_file
from utils.hashing import compute_report_hash, derive_contract_addr

logger    = logging.getLogger(__name__)
upload_bp = Blueprint('upload', __name__)


def _event(data: dict) -> str:
    """Format a dict as an SSE-style data line."""
    return f"data: {json.dumps(data)}\n\n"


@upload_bp.route('/audit/upload', methods=['POST'])
def upload():
    # ── Validate before streaming starts (can still return JSON errors) ────
    if 'file' not in request.files:
        return _json_error("No file provided.", "NO_FILE", 400)

    file = request.files['file']
    valid, error_msg = validate_sol_file(file)
    if not valid:
        code = "INVALID_FILE_TYPE" if "sol" in error_msg.lower() else "FILE_TOO_LARGE"
        return _json_error(error_msg, code, 400)

    source_code = file.read().decode('utf-8', errors='replace')
    filename    = file.filename

    def generate():
        # ── Step 1: AI Analysis ────────────────────────────────────────────
        yield _event({"status": "analyzing", "step": 1,
                       "message": "AI is analyzing your contract..."})

        try:
            report = ai_service.analyze(source_code, filename)
        except Exception as e:
            logger.warning(f"Gemini failed ({type(e).__name__}) — rule-based fallback")
            report = fallback_service.analyze(source_code, filename)

        # ── Step 2: IPFS Upload ────────────────────────────────────────────
        yield _event({"status": "storing", "step": 2,
                       "message": "Uploading report to IPFS..."})

        try:
            ipfs_cid, ipfs_url = ipfs_service.upload_report(report)
        except Exception as e:
            logger.error(f"IPFS upload failed: {e}")
            yield _event({"status": "error", "error": "IPFS upload failed.",
                           "code": "IPFS_FAILURE"})
            return

        # ── Compute hashes ─────────────────────────────────────────────────
        report_hash_hex   = compute_report_hash(report)
        report_hash_bytes = bytes.fromhex(
            report_hash_hex[2:] if report_hash_hex.startswith('0x') else report_hash_hex
        )
        contract_addr = derive_contract_addr(source_code)

        # ── Step 3: Blockchain TX (non-blocking) ───────────────────────────
        yield _event({"status": "anchoring", "step": 3,
                       "message": "Submitting to Ethereum Sepolia..."})

        try:
            tx_hash = blockchain_service.store_audit(
                contract_addr, report_hash_bytes, report['severity'], ipfs_cid
            )
        except Exception as e:
            logger.error(f"Blockchain TX failed: {e}")
            yield _event({"status": "error", "error": "On-chain storage failed.",
                           "code": "BLOCKCHAIN_FAILURE"})
            return

        logger.info(f"Audit complete (TX submitted) | tx={tx_hash} | severity={report['severity']}")

        # ── Done — return everything except fixed_code ─────────────────────
        yield _event({
            "status":       "done",
            "txHash":       tx_hash,
            "ipfsCID":      ipfs_cid,
            "ipfsUrl":      ipfs_url,
            "reportHash":   report_hash_hex,
            "severity":     report['severity'],
            "verdict":      report['verdict'],
            "analysisType": report.get('analysis_type', 'ai'),
            "sourceCode":   source_code,   # frontend stores for /api/audit/fix
            "report":       report
        })

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':     'no-cache',
            'X-Accel-Buffering': 'no',   # disable nginx buffering on Render
        }
    )


def _json_error(msg: str, code: str, status: int):
    from flask import jsonify
    return jsonify({"error": msg, "code": code}), status
