import os
import json
import logging
from web3 import Web3
from eth_account import Account

logger = logging.getLogger(__name__)

PRIVATE_KEY      = os.environ.get('PRIVATE_KEY', '')
INFURA_URL       = os.environ.get('INFURA_URL', '')
CONTRACT_ADDRESS = os.environ.get('CONTRACT_ADDRESS', '')

# Load ABI
_abi_path = os.path.join(os.path.dirname(__file__), '..', 'abi', 'AuditChain.json')
with open(_abi_path) as f:
    ABI = json.load(f)

# Web3 + contract setup
w3 = Web3(Web3.HTTPProvider(INFURA_URL))
contract = w3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT_ADDRESS) if CONTRACT_ADDRESS else None,
    abi=ABI
)

# Backend wallet
wallet = Account.from_key(PRIVATE_KEY) if PRIVATE_KEY else None


def store_audit(contract_addr: str, report_hash_bytes: bytes, severity: str, ipfs_cid: str) -> str:
    """
    Call storeAuditReport() on AuditChain.sol.
    Signs TX with backend wallet private key.
    Waits for receipt (up to 120 seconds).
    Returns TX hash as '0x...' string.
    """
    nonce     = w3.eth.get_transaction_count(wallet.address)
    gas_price = w3.eth.gas_price

    tx = contract.functions.storeAuditReport(
        Web3.to_checksum_address(contract_addr),
        report_hash_bytes,
        severity,
        ipfs_cid
    ).build_transaction({
        'from':     wallet.address,
        'nonce':    nonce,
        'gasPrice': gas_price,
        'gas':      300_000,
        'chainId':  11155111,  # Sepolia chain ID
    })

    signed  = w3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
    # web3 7.x uses raw_transaction (snake_case)
    raw_tx  = signed.raw_transaction if hasattr(signed, 'raw_transaction') else signed.rawTransaction
    tx_hash = w3.eth.send_raw_transaction(raw_tx)
    tx_hex  = '0x' + tx_hash.hex()

    logger.info(f"TX submitted | hash={tx_hex}")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    logger.info(f"TX confirmed | block={receipt.blockNumber} | hash={tx_hex}")

    return tx_hex


def _normalize_tx_hash(tx_hash: str) -> bytes:
    """Convert '0x...' string to bytes for web3 calls."""
    clean = tx_hash.lstrip('0x')
    return bytes.fromhex(clean)


def decode_audit_event(tx_hash: str) -> dict:
    """
    Fetch TX receipt and decode the AuditStored event.
    Returns event args dict with reportHash as '0x...' hex string.
    Raises LookupError('TX_NOT_FOUND') if TX doesn't exist.
    Raises LookupError('EVENT_NOT_FOUND') if TX has no AuditStored event.
    """
    tx_bytes = _normalize_tx_hash(tx_hash)
    receipt  = w3.eth.get_transaction_receipt(tx_bytes)

    if receipt is None:
        raise LookupError("TX_NOT_FOUND")

    events = contract.events.AuditStored().process_receipt(receipt)

    if not events:
        raise LookupError("EVENT_NOT_FOUND")

    args = dict(events[0]['args'])

    # Convert bytes32 reportHash to hex string
    if isinstance(args.get('reportHash'), bytes):
        args['reportHash'] = '0x' + args['reportHash'].hex()

    return args


def get_audit_record(contract_addr: str) -> dict:
    """
    Call getAuditRecord(contractAddr) on-chain.
    Returns dict: {reportHash, timestamp, severity, exists}.
    Raises LookupError('RECORD_NOT_FOUND') if no record exists.
    """
    try:
        report_hash, timestamp, severity, exists = (
            contract.functions.getAuditRecord(
                Web3.to_checksum_address(contract_addr)
            ).call()
        )
    except Exception as e:
        if "No audit found" in str(e):
            raise LookupError("RECORD_NOT_FOUND")
        raise

    return {
        "reportHash": '0x' + report_hash.hex() if isinstance(report_hash, bytes) else report_hash,
        "timestamp":  timestamp,
        "severity":   severity,
        "exists":     exists
    }
