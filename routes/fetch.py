import re
import logging
from flask import Blueprint, request, jsonify
from services import blockchain_service

logger   = logging.getLogger(__name__)
fetch_bp = Blueprint('fetch', __name__)

_TX_RE   = re.compile(r'^0x[a-fA-F0-9]{64}$')
_GATEWAY = "https://gateway.pinata.cloud/ipfs/"


@fetch_bp.route('/fetch', methods=['GET'])
def fetch():
    tx_hash = request.args.get('tx', '').strip()

    if not tx_hash:
        return jsonify({"error": "tx query parameter is required.", "code": "INVALID_TX_FORMAT"}), 400

    if not _TX_RE.match(tx_hash):
        return jsonify({"error": "Invalid transaction hash format.", "code": "INVALID_TX_FORMAT"}), 400

    # ── Decode AuditStored event ───────────────────────────────────────────
    try:
        args = blockchain_service.decode_audit_event(tx_hash)
    except LookupError as e:
        code = str(e)
        messages = {
            "TX_NOT_FOUND":    "Transaction not found on Sepolia.",
            "EVENT_NOT_FOUND": "Not an AuditChain transaction."
        }
        return jsonify({"error": messages.get(code, "Event not found."), "code": code}), 404
    except Exception as e:
        logger.error(f"Fetch decode failed: {e}")
        return jsonify({"error": "Failed to read transaction.", "code": "DECODE_FAILURE"}), 500

    # ── Get on-chain record ────────────────────────────────────────────────
    try:
        record = blockchain_service.get_audit_record(args['contractAddr'])
    except LookupError:
        return jsonify({"error": "No audit record at this address.", "code": "RECORD_NOT_FOUND"}), 404

    ipfs_cid = args.get('ipfsCID', '')

    return jsonify({
        "txHash":       tx_hash,
        "contractAddr": args['contractAddr'],
        "reportHash":   args['reportHash'],
        "severity":     args.get('severity', record['severity']),
        "timestamp":    record['timestamp'],
        "ipfsCID":      ipfs_cid,
        "ipfsUrl":      f"{_GATEWAY}{ipfs_cid}",
        "verified":     True
    }), 200
