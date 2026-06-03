import os
import logging
import requests

logger = logging.getLogger(__name__)

PINATA_API_KEY    = os.environ.get('PINATA_API_KEY', '')
PINATA_SECRET_KEY = os.environ.get('PINATA_SECRET_KEY', '')
PINATA_URL        = "https://api.pinata.cloud/pinning/pinJSONToIPFS"
GATEWAY_BASE      = "https://gateway.pinata.cloud/ipfs/"


def build_ipfs_url(cid: str) -> str:
    return f"{GATEWAY_BASE}{cid}"


def upload_report(report: dict) -> tuple:
    """
    Upload report dict as JSON to Pinata IPFS.
    Returns (cid, ipfs_url).
    Raises Exception if upload fails.
    """
    headers = {
        "pinata_api_key":        PINATA_API_KEY,
        "pinata_secret_api_key": PINATA_SECRET_KEY,
        "Content-Type":          "application/json"
    }

    response = requests.post(PINATA_URL, json=report, headers=headers, timeout=30)

    if response.status_code != 200:
        logger.error(f"Pinata upload failed: {response.status_code} — {response.text}")
        raise Exception(f"Pinata upload failed: {response.status_code}")

    cid = response.json()["IpfsHash"]
    url = build_ipfs_url(cid)
    logger.info(f"IPFS upload complete | CID={cid}")
    return cid, url
