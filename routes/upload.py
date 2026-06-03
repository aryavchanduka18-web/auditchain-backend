import logging
from flask import Blueprint, request, jsonify
from services import ai_service, fallback_service, ipfs_service, blockchain_service
from utils.validation import validate_sol_file
from utils.hashing import compute_report_hash, derive_contract_addr

logger    = logging.getLogger(__name__)
upload_bp = Blueprint('upload', __name__)


@upload_bp.route('/audit/upload', methods=['POST'])
def upload():
    # ── 1. Validate file ───────────────────────────────────────────────────
    if 'file' not in request.files:
        return jsonify({"error": "No file provided.", "code": "NO_FILE"}), 400

    file = request.files['file']
    valid, error_msg = validate_sol_file(file)
    if not valid:
        code = "INVALID_FILE_TYPE" if "sol" in error_msg.lower() else "FILE_TOO_LARGE"
        return jsonify({"error": error_msg, "code": code}), 400

    source_code = file.read().decode('utf-8', errors='replace')
    filename    = file.filename

    # ── 2. AI analysis (Gemini, with automatic fallback on any failure) ─────
    try:
        report = ai_service.analyze(source_code, filename)
    except Exception as e:
        logger.warning(f"Gemini failed ({type(e).__name__}: {e}) — activating rule-based fallback")
        report = fallback_service.analyze(source_code, filename)

    # ── 3. Upload full report to IPFS ──────────────────────────────────────
    try:
        ipfs_cid, ipfs_url = ipfs_service.upload_report(report)
    except Exception as e:
        logger.error(f"IPFS upload failed: {e}")
        return jsonify({"error": "IPFS upload failed. Audit not stored.", "code": "IPFS_FAILURE"}), 500

    # ── 4. Compute hashes and derive contract address ──────────────────────
    report_hash_hex   = compute_report_hash(report)
    report_hash_bytes = bytes.fromhex(report_hash_hex.lstrip('0x'))
    contract_addr     = derive_contract_addr(source_code)

    # ── 5. Store on Ethereum Sepolia ───────────────────────────────────────
    try:
        tx_hash = blockchain_service.store_audit(
            contract_addr,
            report_hash_bytes,
            report['severity'],
            ipfs_cid
        )
    except Exception as e:
        logger.error(f"Blockchain TX failed: {e}")
        return jsonify({"error": "On-chain storage failed.", "code": "BLOCKCHAIN_FAILURE"}), 500

    logger.info(f"Audit stored | tx={tx_hash} | severity={report['severity']}")

    return jsonify({
        "txHash":       tx_hash,
        "ipfsCID":      ipfs_cid,
        "ipfsUrl":      ipfs_url,
        "reportHash":   report_hash_hex,
        "severity":     report['severity'],
        "verdict":      report['verdict'],
        "analysisType": report.get('analysis_type', 'ai'),
        "report":       report
    }), 200
