# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

> SIH 2026 — Problem Statement 26159 | National Technical Research Organisation (NTRO)

## Architecture

```
PCAP File → Go Parser Engine → JSON → Python AI Engine → Go API → React Dashboard
```

| Component | Tech Stack | Directory |
|-----------|-----------|-----------|
| Traffic Generator | Bash + OpenSSL | `testdata/` |
| PCAP Parser | Go + gopacket | `parser/` |
| AI Risk Engine | Python + XGBoost + IsolationForest | `ai_engine/` |
| API Backend | Go + Gin + PostgreSQL | `backend/` |
| SOC Dashboard | Next.js + Tailwind + Recharts | `dashboard/` |

## Quick Start

```bash
# 1. Generate test PCAPs
cd testdata && bash generate_certs.sh && bash generate_traffic.sh

# 2. Build & run parser
cd parser && go build -o ../bin/parser ./cmd/parser
../bin/parser --pcap ../testdata/output/*.pcap --output sessions.json

# 3. Run AI engine
cd ai_engine && pip install -r requirements.txt
python main.py --input ../parser/sessions.json --output results.json

# 4. Start API backend
cd backend && go run ./cmd/server

# 5. Start dashboard
cd dashboard && npm install && npm run dev
```

## License

MIT
