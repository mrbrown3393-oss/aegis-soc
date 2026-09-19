# Aegis SOC — Advanced Zero-Trust Security Operations Platform

Professional defensive cybersecurity operations center with an **embedded Grok AI Analyst**.

**GitHub:** https://github.com/mrbrown3393-oss/aegis-soc

Runs fully locally (no Replit required). All telemetry is simulated.

## Demo accounts

| Email | Role | Password |
|-------|------|----------|
| `admin@aegis.demo` | admin | `AegisDemo2026!` |
| `analyst@aegis.demo` | analyst | `AegisDemo2026!` |
| `viewer@aegis.demo` | viewer | `AegisDemo2026!` |

## Run locally

```bash
git clone https://github.com/mrbrown3393-oss/aegis-soc.git
cd aegis-soc
npm install
cd client && npm install && cd ..
npm run dev
```

Open http://localhost:5173

Optional live Grok: copy `.env.example` to `.env` and set `XAI_API_KEY`.
Never commit `.env`.
