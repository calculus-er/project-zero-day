# Omium demo for judges (~60 seconds)

## Before the demo

1. Docker arena: `docker compose up -d` (target on port 5000)
2. Backend: `cd backend` → `uvicorn main:app --reload --port 8000`
3. Frontend: `cd frontend` → `npm run dev` (war room on http://localhost:5173)
4. In `backend/.env`: `OMIUM_TRACING_ENABLED=true`, valid `OMIUM_API_KEY`, `OMIUM_PROJECT=zero-day`
5. Optional: `omium project push` from repo root (workflow `id` in `omium.toml` must be a UUID)

**Do not leave the Omium Cost/Overview tab open** — it polls the API and burns credits.

## Where to click in Omium (your sidebar)

Docs mention `/automations` — that URL **404s** on current Omium. Use these instead:

| Goal | Where |
|------|--------|
| Your project / workflows | **AI Systems** → https://app.omium.ai/ai-systems → open **zero-day** |
| Project after `omium project push` | https://app.omium.ai/automation?project=zero-day |
| Each scan as a run | **Overview** or **Runs** — https://app.omium.ai/runs |
| Spans for a run | Open the execution → trace / spans |

## What to show judges

### A — Omium + live scan

1. **AI Systems** → **zero-day** (or open automation link above)
2. **Runs** (or Overview) in another tab
3. War room → **Start Scan**
4. Refresh Runs: new row `running` → `completed`, `output_data.outcome: breached`
5. Open that run → spans: `SCAN_STARTED`, `ALPHA_RECON`, `BETA_STRIKE_ATTEMPT_*`, `BREACH_CONFIRMED`

### B — War room (local)

Matrix dashboard: agent feed + breach alert (usually attempt 2+).

### C — One-liner

> "Each scan creates an Omium Execution Engine run, binds the SDK execution ID, streams agent spans, and closes with breach outcome — visible under Runs and AI Systems."

## Troubleshooting

| Symptom | Fix |
|--------|-----|
| `/automations` 404 | Normal — use **AI Systems** or `/automation?project=zero-day` |
| 0 runs | `OMIUM_PROJECT=zero-day` in `.env`; restart uvicorn |
| Credits draining idle | Close Cost tab |

```powershell
Invoke-RestMethod http://localhost:8000/status
# omium_tracing: true, omium_execution_id while scan runs
```
