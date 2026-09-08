## CyberBug

**CyberBug** — AI-driven cybersecurity detection platform for unidirectional IP traffic.


It evaluates:

```text
Traffic × Behavior × Baseline × AI Detection × Risk Scoring
```

The system observes, analyzes, detects, explains, and alerts — but never interferes with the protected network.

## System design

```text
Protected Network (Servers, Applications, Network Devices)
  └─ One-Way IP Traffic (No Return Path)
       └─ Passive Traffic Monitor
            └─ Traffic/Flow Processing
                 └─ Feature Extraction
                      ├─ Normal Behaviour Baseline
                      ├─ AI Detection Engine (Hybrid)
                      │   ├─ Rule Engine
                      │   ├─ Machine Learning Models
                      │   └─ Anomaly Detection
                      ├─ Threat Detection & Classification
                      ├─ Threat Behaviour Fingerprint (DNA)
                      ├─ Explainable Evidence
                      └─ Risk & Confidence Scoring
                           ├─ Alert Correlation
                           ├─ Attack Story / Timeline
                           ├─ Incident Management
                           ├─ Response Recommendation (Advisory Only)
                           └─ SOC Dashboard
                                └─ Security Analyst (Human-in-the-Loop)
                                     └─ Feedback Loop
```

### Detection flow

```text
Traffic Capture → Flow Processing → Feature Extraction
→ Normal Baseline Comparison → AI Detection (Rules + ML + Anomaly)
→ Threat Classification → Threat DNA Fingerprint
→ Explainable Evidence → Risk & Confidence Scoring
→ Alert Correlation → Attack Story → Incident → Advisory Response
→ SOC Dashboard → Analyst Review → Feedback Loop
```

Hard constraints: No traffic sent back. No probes or scans. No handshakes. No mitigation commands across the ingest path.

## Key Capabilities

- Works in One-Way Environments
- AI + Rules + Anomaly (Hybrid)
- Adaptive Baseline per Host/Network
- Threat Behaviour Fingerprint (DNA)
- Explainable Detection
- Alert Correlation & Attack Story
- Risk-Based Prioritization
- Next-Stage Risk Estimation
- Advisory Response (No Active Control)
- Human-in-the-Loop Feedback

## Threat Detection

Supported threat types:
- DDoS / Protocol Flood
- C2 Beaconing
- DGA Activity
- DNS Tunnelling
- Scanning Activity
- Other Anomalies

## Privacy boundary

CyberBug does not collect keystrokes, passwords, screenshots, screen recordings, webcam/microphone data, personal chats, or document contents. It collects security metadata such as authentication events, devices, sessions, resource categories, target systems, privilege activity, access frequency, source IP metadata, and event sequences.

## Local setup

Requirements: Python 3.12+, Node.js 20+, npm.

```bash
git clone https://github.com/NandaKumar876/cyberbug.git
cd cyberbug/backend
python3 -m pip install -e '.[dev]'
python3 -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

In another terminal:

```bash
cd cyberbug/frontend
npm install
npm run dev
```

Open `http://localhost:5173`. SQLite is created automatically for development. PostgreSQL setup is documented in [docs/production-database.md](docs/production-database.md).

## Verification

```bash
cd backend
python3 -m pytest -q
python3 -m compileall -q app
cd ../frontend
npm run build
```

## Private-network testing

Run the backend on an authorized private interface:

```bash
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Find the control-plane address:

```bash
# macOS
ipconfig getifaddr en0

# Windows
ipconfig
```

From an authorized endpoint:

```powershell
Test-NetConnection CONTROL_PLANE_IP -Port 8000
Invoke-WebRequest http://CONTROL_PLANE_IP:8000/health
```

Do not expose port 8000 to the public internet. Use a private LAN/VPN and configure `CYBERBUG_COLLECTOR_TOKEN` on both backend and collector when authentication is enabled.

## Windows collector

Endpoint collection is Windows-only because it uses Windows Security Event Logs, WEF/WEC ForwardedEvents, and optional pywin32/Sysmon enrichment. The backend, database, simulation, and frontend can run on Windows, macOS, or Linux.

```powershell
cd backend
$env:CYBERBUG_API_URL="http://CONTROL_PLANE_IP:8000"
$env:CYBERBUG_COLLECTOR_TOKEN="replace-with-a-random-secret"
python -m app.collector.service --source security --endpoint http://CONTROL_PLANE_IP:8000 --collector-id MGR-PC --interval 5
```

For WEC:

```powershell
python -m app.collector.service --source forwarded --endpoint http://CONTROL_PLANE_IP:8000 --collector-id WEC-01 --interval 5
```

Collector liveness: `GET /api/v1/collectors`.

## API quick reference

| Area | Endpoints |
| --- | --- |
| Health | `GET /health`, `GET /api/v1/collectors` |
| Overview | `GET /api/v1/overview` |
| Sessions | `GET /api/v1/sessions`, `GET /api/v1/sessions/{id}`, `/risk`, `/features`, `/timeline` |
| Containment | `POST /api/v1/sessions/{id}/contain` |
| Events | `GET/POST /api/v1/events` |
| Devices/traffic | `GET /api/v1/devices`, `GET /api/v1/traffic` |
| Identities/baselines | `/api/v1/identities`, `/api/v1/identities/{id}/baseline` |
| Incidents | `/api/v1/incidents`, `/api/v1/incidents/{id}` |
| Deception | `/api/v1/deception/resources`, `/sessions`, `/interactions` |
| Corporate app | `/dashboard`, `/reports`, `/admin`, `/files/...`, `/export` with `X-CyberBug-Session` |
| Simulation | `/api/v1/simulation/scenarios`, `POST /run`, `POST /reset` |
| WebSockets | `/ws/events`, `/ws/risk`, `/ws/incidents` |

## Repository layout

```text
backend/app/collector       Windows Security/WEF readers and service
backend/app/normalization   Typed normalized event contract
backend/app/privacy         Pseudonymization and sanitization
backend/app/sessions        Correlation and within-session drift
backend/app/features        Rolling feature extraction
backend/app/baseline        Personal/peer baselines and poisoning guard
backend/app/detection       Rules, sequence memory, intent
backend/app/risk             Risk composition and thresholds
backend/app/policy           Override and deception gates
backend/app/deception        Synthetic resources and evidence
backend/app/corporate        Controlled application enforcement
backend/app/db               SQLAlchemy models and repositories
backend/app/simulation       End-to-end demo scenarios
backend/tests                API, detection, baseline, policy, collector tests
frontend/src                 React/Vite SOC console
docs                         Architecture, Windows, database, UI notes
```

## Limitations

- Endpoint telemetry is Windows-only.
- An IP address alone cannot identify the physical person using a session.
- Website visibility requires an authorized proxy, DNS, or browser-security integration.
- Arbitrary file-copy/download visibility requires endpoint or application-specific telemetry.
- Decoys work only for routes protected by the controlled corporate-app gateway.
- CyberBug is a focused detection platform, not a full EDR or SIEM replacement.
