# Emissary: an AI SOC analyst

**Emissary** is an online, admin-only security operations (SOC) triage assistant. An analyst uploads SSH, web-server or firewall logs; Emissary finds suspicious activity with explainable rules, investigates each alert with a tool-using AI agent, maps it to MITRE ATT&CK, scores severity (P1 to P4), and saves a reviewable incident with a full audit trail. A **Master** agent (Part 2) correlates alerts into cases and directs the emissaries.

> Built for the HEC-NCEAC & PEC Generative & Agentic AI Training, Cohort 11, Hackathon 2.
> Author: Muhammad Zain Nasir (MPhil Electronics, Quaid-i-Azam University).

- **Live app:** https://emissary-g03r.onrender.com (login required; free hosting tier, first load can take about a minute)
- **Code:** this repository
- **PRD, slides and demo video:** see the submission form

## What it does

| Step | What happens |
|---|---|
| 1. Ingest | Upload a `.log`/`.txt` file or paste log lines. Types: SSH auth, web access (Apache/Nginx combined), firewall (UFW). |
| 2. Parse and detect | Three **emissaries** (one per log source) parse events and run rule detectors: SSH brute force and compromised accounts, port scans, web attacks (SQL injection, path traversal, XSS, command injection, scanner user-agents). |
| 3. Enrich | IP reputation (local blocklist, optional AbuseIPDB), internal/external check, ATT&CK mapping (T1110, T1078, T1595/T1046, T1190). |
| 4. Score | Explainable severity P1 to P4; every point is recorded with a reason ("why the rules fired"). |
| 5. Investigate | An AI agent calls **read-only tools** (query events, enrich IP, related alerts, MITRE lookup) and returns a validated incident: verdict, confidence, evidence, actions. |
| 6. Review | Admin web app: incident list, detail page, status, true/false-positive feedback, Markdown report export, audit log of every tool call and sign-in. |
| 7. Master (Part 2) | Correlates alerts from different sources into **cases** and dispatches emissaries with focused questions. |

Recommended actions are suggestions for a human. **Emissary never executes anything.**

## Architecture

```
 Admin browser --HTTPS--> FastAPI app (login, CSRF, rate limit, security headers)
                              |
        upload ----> Emissary registry: auth | web | firewall
                         parse -> detect -> enrich -> ATT&CK -> severity
                              |
                    Agent loop (LLM + read-only tools, bounded, guarded)
                              |
              Master: correlate alerts into cases, dispatch emissaries
                              |
                    SQLite: uploads, alerts, incidents, tool_calls (audit), feedback
```

Stack: Python 3.11+, FastAPI, Jinja2, SQLite, Pydantic, any OpenAI-compatible LLM endpoint (tested with Google Gemini free tier and OpenRouter), deployed on Render.

## Safety and security design

- **Read-only tools only.** The agent cannot change anything. A test fails if a tool is added or if the tools module imports file, process or socket access.
- **Prompt-injection defense.** Log text is treated as untrusted data in the prompt, and code guardrails the model cannot override: severity can move at most one level from the rule-based score, and a P1 can never be dismissed automatically.
- **Bounded runs.** Maximum tool rounds, token ceiling and time limit per alert. If anything fails, a clearly flagged "needs review" incident is saved instead of an error or a silent all-clear.
- **No silent failures.** A file that cannot be parsed as the chosen log type is reported as "nothing was checked".
- **Web security.** PBKDF2 password hash, signed HttpOnly session cookie, CSRF tokens, login rate limiting, strict Content-Security-Policy, escaped output, no public API docs, fails closed without credentials.
- **Secrets** only in environment variables (`.env` is git-ignored).

## Quick start (local)

```bash
git clone <this-repo> && cd emissary
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt pytest
python data/samples/gen_logs.py          # generate synthetic sample logs
cp .env.example .env                     # then fill in the values below
python make_hash.py                      # prints ADMIN_USER / ADMIN_PASSWORD_HASH / SESSION_SECRET for .env
uvicorn app.main:app --reload            # open http://127.0.0.1:8000
```

### Configuration (`.env`)

| Variable | Purpose |
|---|---|
| `LLM_BASE_URL` | OpenAI-compatible endpoint, e.g. `https://generativelanguage.googleapis.com/v1beta/openai/` or `https://openrouter.ai/api/v1` |
| `LLM_API_KEY` | Key for that provider |
| `LLM_MODEL` | Model name, e.g. `gemini-3.1-flash-lite` |
| `LLM_MAX_RETRIES` | Retries on provider errors (use 0 on tight free quotas) |
| `ADMIN_USER`, `ADMIN_PASSWORD_HASH`, `SESSION_SECRET` | Admin login (generate with `make_hash.py`) |
| `TRUST_PROXY=1` | Set when running behind Render, Caddy or Nginx |
| `EMISSARY_DB` | SQLite path (use `/tmp/emissary.db` on free hosts) |
| `ENRICH_ONLINE=1`, `ABUSEIPDB_API_KEY` | Optional online IP reputation |

Without an LLM key the app still runs: detection works and alerts are saved as flagged "needs review" incidents.

## Tests and evaluation

```bash
python -m pytest -q                      # 96 tests, no network needed
python run_eval.py                       # detection layer vs labelled ground truth, free and offline
python run_eval.py --llm --delay 10 --only auth_bruteforce_compromise,fp_forgotten_password
python run_eval.py --feedback            # model verdicts vs your own true/false-positive labels
python check_site.py https://your-site   # 24 security checks against a running site
```

`data/eval/ground_truth.json` holds 8 labelled cases (5 attacks or look-alikes, 3 benign). The evaluator reports verdict accuracy, severity agreement, ATT&CK match, **dangerous misses** (an attack called a false positive), false alarms, fallback rate, tokens and consistency.

### Observed results (synthetic logs)

| Case | Result |
|---|---|
| SSH brute force then login | P1 true_positive, T1110 + T1078 (live site, gemini-3.1-flash-lite, 2 rounds, 6,751 tokens) |
| Web attacks (sqlmap, 4 attack types) | P2 true_positive, T1190 |
| Port scan | P3 true_positive, T1595 |
| One user's mistyped password | likely_false_positive, P3 |
| Prompt injection planted in logs | P2 true_positive; planted text flagged as evasion |
| Benign logs (3 files) | 0 alerts, no AI call |
| Detection layer | 8/8 cases match ground truth |
| Dangerous misses in evaluated runs | 0 |

An early evaluation run hit the per-alert token ceiling and was saved as a flagged fallback; the ceiling was raised. These numbers come from synthetic logs and show that the system works on these cases, not how it performs on real traffic.

## Deploy (Render, free tier)

1. Push to GitHub. On Render choose **New > Web Service**, pick the repo.
2. Build: `pip install -r requirements.txt`. Start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`. Health check: `/healthz`.
3. Set the environment variables above (plus `TRUST_PROXY=1`, `EMISSARY_DB=/tmp/emissary.db`).
4. Verify with `python check_site.py https://<your-service>.onrender.com`.

## Project structure

```
app/
  web.py, auth.py          admin web app, login, CSRF, headers
  pipeline.py              upload -> emissary -> agent -> master -> storage
  emissaries/              Emissary base class, registry, auth / web / firewall emissaries
  detectors/               brute force, port scan, web attacks, severity scoring
  enrich/                  IP reputation, ATT&CK map, IOC extraction
  agent/                   investigation loop, read-only tools, prompts, guardrails
  cases.py, master.py      Part 2: case correlation and Master agent
  db.py, reports.py        SQLite storage, audit trail, feedback, Markdown reports
  evaluation.py            evaluation harness
data/samples/              synthetic logs (attacks, false-positive, prompt-injection, benign)
data/eval/ground_truth.json
run_eval.py, check_site.py, make_hash.py, run_*.py
tests/                     96 tests
```

## Limitations

- AI answers can contain small factual slips (for example a miscounted event); raw log lines and human review are always shown.
- Free AI quotas can block analysis; the app then saves a flagged "needs review" incident.
- The free host resets its database on restart and sleeps after about 15 idle minutes. Web-attack logs cannot be uploaded to the public site because the host's firewall blocks attack strings; run them locally.
- Rule-based detection on three log types, uploaded files only (no live SIEM feed yet).
- Evaluated on synthetic data only.

## Roadmap (Master, Part 2)

Done: emissary interface and registry, case correlation, Master agent, feedback storage, evaluation harness. Next: analyst feedback as Master memory, persisted cases in the UI, human-approved response playbooks (dry run), real datasets and a SIEM feed (Wazuh/Suricata), persistent hosting.

## Acknowledgements

Design informed by agentic-AI security practice, including Omar Santos, *Agentic AI for Cybersecurity*, and the MITRE ATT&CK framework. Sample logs are synthetic and use reserved documentation IP ranges.
