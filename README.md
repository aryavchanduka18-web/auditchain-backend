
# AuditChain — Backend

Flask API server for AuditChain — an AI-powered smart contract security auditing platform that anchors audit reports permanently on Ethereum.

## Live Demo
**Frontend:** https://auditchain-app.netlify.app  
**Contract:** https://sepolia.etherscan.io/address/0x6769bdb7576bf2fb70fb3d4b5b1af4bb141d8084

## What It Does
1. Accepts a Solidity `.sol` file via POST request
2. Runs AI vulnerability analysis (Gemini 2.0 Flash) with rule-based fallback
3. Uploads the full audit report to IPFS via Pinata
4. Computes `keccak256(report)` and stores it on Ethereum Sepolia
5. Returns a transaction hash — the permanent, tamper-proof proof of audit
6. Fetch and verify any audit using only the TX hash

## Tech Stack
| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, Flask |
| Blockchain | Web3.py v7, Ethereum Sepolia |
| RPC Provider | Alchemy |
| AI Analysis | Google Gemini 2.0 Flash |
| IPFS Storage | Pinata |
| Deployment | Render.com |

## API Endpoints
| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/api/audit/upload` | Upload `.sol` file → returns `txHash`, `ipfsUrl`, `reportHash`, `severity` |
| `GET` | `/api/fetch?tx={hash}` | Fetch full audit record from TX hash |
| `GET` | `/api/verify?tx={hash}` | Verify audit authenticity from TX hash |

## Local Setup
```bash
git clone https://github.com/aryavchanduka18-web/auditchain-backend
cd auditchain-backend
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
cp .env.example .env         # Fill in your keys
python app.py
Environment Variables
PRIVATE_KEY=          # MetaMask wallet private key (Sepolia only)
INFURA_URL=           # Alchemy/Infura Sepolia RPC URL
CONTRACT_ADDRESS=     # Deployed AuditChain.sol address
PINATA_API_KEY=       # Pinata API key
PINATA_SECRET_KEY=    # Pinata secret key
GEMINI_API_KEY=       # Google AI Studio API key
Architecture
.sol file → Gemini AI Analysis → Pinata IPFS → keccak256 hash
         → storeAuditReport() on Ethereum Sepolia
         → AuditStored event emitted (contractAddr, reportHash, severity, ipfsCID)
         → Transaction Hash returned to user
Smart Contract
AuditChain.sol is deployed on Ethereum Sepolia.
The contract stores keccak256(reportJSON) mapped to a deterministic address derived from source code.
ipfsCID is emitted in the AuditStored event — retrievable from any TX hash forever.
