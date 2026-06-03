import json
from eth_utils import keccak
from web3 import Web3


def canonical_json(data: dict) -> bytes:
    """
    Serialize dict to deterministic JSON bytes.
    Keys sorted alphabetically, no whitespace.
    MUST be used consistently for all reportHash computations.
    """
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')


def compute_report_hash(report: dict) -> str:
    """
    Compute keccak256 of canonical JSON of the report dict.
    Returns '0x' + 64 hex chars.
    """
    raw = keccak(canonical_json(report))
    return '0x' + raw.hex()


def derive_contract_addr(source_code: str) -> str:
    """
    Derive a deterministic Ethereum checksum address from Solidity source code.
    Uses keccak256 of source bytes, takes last 20 bytes as address.
    Internal use only — never exposed to users.
    Same source always produces the same address.
    """
    code_hash = keccak(text=source_code)
    return Web3.to_checksum_address('0x' + code_hash.hex()[-40:])
