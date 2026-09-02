# CyberBug â€” Windows-Only Insider Threat Detection & Adaptive Deception Prototype

## 1. Project Summary

**CyberBug** is a Windows-focused, privacy-conscious insider-threat and compromised-account detection prototype.

The system is designed for a realistic enterprise scenario where an attacker or malicious employee may operate using **valid corporate credentials**. Traditional authentication can succeed because the username and password are correct, so the system continuously evaluates whether the authenticated activity still looks consistent with the expected user, session, device context, role, and historical behavior.

The prototype combines:

- Native Windows security telemetry
- Agentless-style log collection using Windows Event Forwarding
- Privacy-preserving identity handling
- User/session/device-context correlation
- Personal and peer behavioral baselines
- Unsupervised anomaly detection
- Sequence-aware attack detection
- Explainable deterministic security rules
- Intent classification
- Dynamic session-level risk scoring
- Intent-gated deception
- Graduated containment
- A professional SOC-style dashboard

The core principle is:

> **High anomaly does not mean malicious, and high risk alone never triggers deception.**

Deception is allowed only when the system has both high contextual risk and evidence of attack intent, and no strong verified legitimate context is present.

---

# 2. Problem Statement

Malicious insiders or attackers using stolen employee credentials can behave normally for long periods before gradually accessing sensitive information.

A useful system must:

1. Detect meaningful deviations from normal behavior.
2. Avoid treating ordinary employee activity as suspicious by default.
3. Remain privacy-conscious.
4. Avoid permanently labeling an employee as malicious.
5. Distinguish between identity-level history and individual session/device contexts.
6. Detect low-and-slow attack behavior.
7. Avoid allowing attacker activity to poison the user's baseline.
8. Avoid automatically sending legitimate users into fake environments.
9. Provide explainable evidence to analysts.
10. Contain only the suspicious context whenever possible.

---

# 3. Final Prototype Scope

## Included

The first prototype will support **Windows only**.

It will include:

- Windows Security Event Log ingestion
- Windows Event Forwarding / Windows Event Collector
- Optional Sysmon integration
- Python backend
- Session correlation
- Privacy layer
- Behavioral feature extraction
- Personal baseline
- Peer baseline
- Baseline drift detection
- Isolation Forest anomaly scoring
- Rule engine
- Sequence / n-gram analysis
- Intent classifier
- Dynamic session risk engine
- Controlled corporate application
- Controlled decoy resources
- Session-level containment
- Real-time dashboard
- Simulation scenarios for demo

## Not Included in V1

The following are intentionally out of scope:

- macOS support
- Linux support
- Full EDR functionality
- Keystroke logging
- Screen recording
- Webcam or microphone monitoring
- Reading personal messages
- Reading arbitrary employee document contents
- USB monitoring
- Full process-memory inspection
- Kernel-level endpoint protection
- Automatic permanent user-account disabling
- Fully autonomous production honeypot infrastructure
- Production-scale SIEM replacement
- Production-grade identity provider integration

---

# 4. Core Security Scenario

## Scenario

A malicious employee or attacker gets the credentials of a department manager.

The attacker uses those valid credentials from another corporate Windows machine.

### Normal manager context

```text
Identity: Alice / Manager
Device: MGR-PC
Typical working hours: 09:00â€“18:00
Typical resources:
- Finance dashboard
- Reports
- Management portal

Typical behavior:
- 5â€“30 files/day
- Rare SSH activity
- Rare server enumeration
- Rare privilege-related actions
```

### Suspicious context

```text
Identity: Alice / Manager
Device: EMP-PC
Session: S92

Behavior:
- New device context
- Concurrent manager session exists
- Accesses unseen hosts
- Repeated authentication attempts
- Server discovery
- Admin-resource discovery
- Credential-hunting activity
- Sensitive data access
```

The system does not immediately say:

```text
"Alice is malicious."
```

It instead evaluates:

```text
Identity Ã— Session Ã— Device Context
```

Example:

```text
Alice
â”‚
â”œâ”€â”€ Session S18 / MGR-PC
â”‚   Risk: 8
â”‚   Status: Normal
â”‚
â””â”€â”€ Session S92 / EMP-PC
    Risk: 84
    Status: High Risk
```

Containment is applied to `S92`, not to Alice's entire identity.

---

# 5. Core Design Principles

## 5.1 Identity Is Not the Same as the Human

A valid account can be abused.

Therefore:

```text
Valid credentials != trusted behavior
```

Authentication proves that a credential was accepted.

Behavioral analysis asks:

> Does the activity after authentication remain consistent with the expected identity and context?

---

## 5.2 Session-Level and Device-Context Scoring

Do not maintain only:

```text
User Risk = 85
```

Maintain:

```text
user Ã— session Ã— device-context
```

The user can still have a long-term aggregate profile, but containment decisions should primarily operate at the suspicious session/context level.

---

## 5.3 Within-Session Drift Detection

Attackers may hijack an already authenticated session.

In that case:

```text
Session X = legitimate
Session Y = attacker
```

may not exist.

Therefore the model compares:

```text
Current 5â€“10 minute window

against

Earlier behavior in the same session

and

The user's long-term baseline
```

Example:

```text
09:00â€“10:30
Reports
Finance dashboard
3 documents

10:31â€“10:36
14 new hosts
SSH attempts
Admin discovery
Credential search
Bulk sensitive access
```

The session ID may not change, but the behavior clearly drifts.

---

## 5.4 Privacy First

The system monitors **security-relevant organizational telemetry**, not the person's private life.

Do not collect:

- Keystrokes
- Passwords
- Screen recordings
- Webcam
- Microphone
- Personal messages
- Personal document contents

Collect:

- Authentication events
- Failed login counts
- Session identifiers
- Device identifiers
- Resource categories
- Access frequency
- Resource sensitivity
- Privilege-related events
- Network/service access metadata
- Security-event sequences

---

## 5.5 Anomaly Does Not Equal Malicious

An employee working late during a deadline may generate unusual behavior.

Therefore:

```text
Anomaly â†’ Additional evidence collection
```

not:

```text
Anomaly â†’ Honeypot
```

---

## 5.6 Deception Is Intent-Gated

The central rule is:

```text
DECEPTION_ALLOWED =

Risk >= HIGH

AND

Intent in {
    RECON,
    CREDENTIAL_HUNTING,
    LATERAL_MOVEMENT,
    EXFIL_ATTEMPT
}

AND

IntentConfidence >= threshold

AND

NO strong legitimate override
```

Risk alone never triggers deception.

---

## 5.7 Strong Legitimate Overrides

Do not treat ordinary MFA success as sufficient proof of legitimacy.

An attacker may have:

- A stolen authenticated session
- A stolen token
- A compromised MFA flow
- A compromised endpoint

Strong legitimate overrides can include:

- Approved bulk-operation ticket
- Approved maintenance window
- Explicit manager/security approval
- Fresh phishing-resistant step-up authentication
- Known scheduled automation
- Explicit SOC-approved exception

---

## 5.8 Baseline Poisoning Resistance

Do not allow suspicious behavior to become the new normal.

Use:

- Median
- Quantiles
- Median Absolute Deviation
- Trimmed windows
- Long-term trusted baseline
- Short-term behavior window
- Suspicion-aware baseline updates

Example:

```text
risk < 30
    normal baseline learning

risk 30â€“50
    heavily reduce baseline learning

risk > 50
    freeze baseline learning
```

Also monitor:

```text
short-term baseline
vs
long-term baseline
```

If the gap moves rapidly, generate a drift warning instead of silently adapting.

---

# 6. High-Level Architecture

```text
                      WINDOWS CORPORATE LAB
                               â”‚
             â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
             â”‚                 â”‚                 â”‚
          MGR-PC            EMP-PC          CORP-SRV
             â”‚                 â”‚                 â”‚
             â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                               â”‚
                      Windows Security Events
                               â”‚
                               â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚ WEF / WEC          â”‚
                    â”‚ Windows Collector  â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚ Python Collector   â”‚
                    â”‚ pywin32            â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚ Event Normalizer   â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚ Privacy Layer      â”‚
                    â”‚ HMAC IDs           â”‚
                    â”‚ Data minimization  â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚ Session Correlator â”‚
                    â”‚ user Ã— session Ã—   â”‚
                    â”‚ device-context     â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚ Feature Engine     â”‚
                    â”‚ 5m / 1h / 24h      â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â”‚
                 â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                 â–¼                         â–¼
        Personal Baseline            Peer Baseline
                 â”‚                         â”‚
                 â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚ ML Anomaly Engine  â”‚
                    â”‚ Isolation Forest   â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â”‚
                 â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                 â–¼            â–¼            â–¼
            Rule Engine   Sequence     Context
                          Engine       Engine
                 â”‚            â”‚            â”‚
                 â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚ Dynamic Risk       â”‚
                    â”‚ Engine             â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚ Intent Engine      â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚ Policy Engine      â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â”‚
                   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                   â–¼                     â–¼
              Real Resource          Decoy Resource
                                           â”‚
                                           â–¼
                                Decoy interaction events
                                           â”‚
                                           â–¼
                                  Confidence increases
                                           â”‚
                                           â–¼
                                Session containment
```

---

# 7. Windows Prototype Environment

Recommended minimum lab:

## 7.1 MGR-PC

Windows 11 VM.

Purpose:

- Represents legitimate department manager
- Generates normal manager activity
- Maintains a normal active session

---

## 7.2 EMP-PC

Windows 11 VM.

Purpose:

- Represents employee/attacker device
- Uses stolen manager credentials
- Generates suspicious behavior

---

## 7.3 CORP-SRV

Windows Server or Windows VM.

Purpose:

- Hosts controlled corporate application
- Hosts selected protected resources
- Generates resource-access telemetry
- Acts as controlled enterprise target

---

## 7.4 SEC-SRV

Windows Server or Windows 11 VM.

Purpose:

- Windows Event Collector
- Python backend
- ML engine
- Database
- Risk engine
- Intent engine
- Decoy service
- API
- Dashboard backend

For a smaller demo, CORP-SRV and SEC-SRV can initially be the same VM.

---

# 8. Windows Telemetry

## 8.1 Primary Collection

Use:

```text
Windows Event Log
      â†“
Windows Event Forwarding
      â†“
Windows Event Collector
      â†“
Python
```

This is preferable to actively polling every endpoint with WinRM/WMI.

WinRM/WMI are useful for remote administration and inventory, but this project needs a continuous event stream.

---

## 8.2 Useful Windows Event IDs

Initial prototype events:

| Event ID | Meaning | Use |
|---|---|---|
| 4624 | Successful logon | Authentication/session start |
| 4625 | Failed logon | Brute-force / anomaly feature |
| 4634 | Logoff | Session ending |
| 4648 | Explicit credentials used | Credential-use signal |
| 4672 | Special privileges assigned | Privileged context |
| 4688 | Process creation | Optional enhanced telemetry |
| 5140 | Network share accessed | Resource access |
| 5145 | Detailed network-share access | Fine-grained access |

Audit policy must be configured for required events.

---

## 8.3 Optional Sysmon

Sysmon can be added later for richer telemetry.

Potential signals:

- Process creation
- Network connection
- DNS activity
- File activity
- Process relationships

Sysmon should be described as **optional enhanced Windows telemetry**, not as purely agentless.

---

# 9. Python Technology Stack

## Backend

- Python 3.12+
- FastAPI
- Uvicorn
- asyncio
- Pydantic

## Windows Integration

- pywin32
- Windows Event Log APIs
- WEF/WEC

## Data / Feature Engineering

- NumPy
- Pandas
- SciPy

## Machine Learning

- scikit-learn
- IsolationForest

## Database

Prototype:

- SQLite

Preferred final hackathon version:

- PostgreSQL
- SQLAlchemy
- Alembic

## Real-Time Updates

- FastAPI WebSockets

## Testing

- pytest

## Frontend

- React
- TypeScript
- Vite
- TanStack Router
- TanStack Query
- TanStack Table
- shadcn/ui
- Tailwind CSS
- Recharts
- Lucide icons

---

# 10. Why Python for V1

Python is preferred for the Windows-only hackathon prototype because it gives faster iteration for:

- Windows log parsing
- Feature engineering
- ML experiments
- Simulation
- API development
- Risk tuning
- Data inspection

Rust can be considered later for:

- High-throughput ingestion
- Hardened endpoint collectors
- Performance-sensitive production services
- Cross-platform low-level collectors

The prototype should prioritize proving the detection model, not language complexity.

---

# 11. Common Security Event Schema

Do not let Windows-specific event formats spread across the entire codebase.

Normalize everything.

Example:

```json
{
  "event_id": "evt_000182",
  "timestamp": "2026-08-22T02:42:18+05:30",
  "identity_id": "USR-A12",
  "session_id": "SES-A817",
  "device_id": "EMP-PC-22",
  "event_type": "AUTH_SUCCESS",
  "event_category": "authentication",
  "source": "EMP-PC-22",
  "target": "CORP-SRV",
  "resource_type": "INTERNAL_APP",
  "resource_sensitivity": 2,
  "action": "login",
  "result": "success",
  "metadata": {}
}
```

---

# 12. Privacy Architecture

Raw identity:

```text
DOMAIN\Alice
```

should not be propagated into the ML system.

Use:

```text
HMAC(
  tenant_secret,
  Windows SID
)
```

Result:

```text
USR-A12
```

Maintain a restricted identity mapping separately.

## Analytics database

```text
USR-A12
SES-A817
risk 84
```

## Restricted identity vault

```text
USR-A12
    â†“
Alice Smith
```

Only authorized incident investigation should resolve the real identity.

---

# 13. Session Correlation

A session entity should contain:

```text
session_id
identity_id
device_id
started_at
last_seen
auth_strength
source_context
risk_score
anomaly_score
sequence_score
intent
intent_confidence
status
```

Possible statuses:

```text
NORMAL
ELEVATED
HIGH
DECEPTION_ELIGIBLE
DECEPTION
CONTAINED
CLOSED
```

---

# 14. Feature Engineering

Generate rolling features for:

- 5 minutes
- 1 hour
- 24 hours
- 7 days
- 30 days

Example session feature vector:

```text
failed_logins
successful_logins
new_device_count
new_server_count
unique_target_count
explicit_credential_events
privileged_events
admin_resource_attempts
share_access_count
sensitive_resource_reads
download_volume
after_hours_score
concurrent_session_count
personal_deviation
peer_deviation
within_session_drift
sequence_risk
decoy_interaction_count
```

---

# 15. Personal Baseline

Learn what is normal for a specific identity.

Example:

```text
USR-A12

Working hours:
09:00â€“18:00

Known devices:
MGR-PC

Typical target count/hour:
2â€“5

Typical failed logins/hour:
0â€“1

Typical sensitive resource reads/day:
10â€“25

Typical SSH activity:
Almost none
```

---

# 16. Peer Baseline

Personal history alone is insufficient.

A new employee may have no reliable personal history.

Use:

```text
Organization
    â†“
Department
    â†“
Role
    â†“
Individual
```

Example:

```text
Manager Peer Group

Finance access:
Common

Report downloads:
Common

SSH server enumeration:
Rare

Credential-store discovery:
Very rare
```

The peer baseline helps answer:

> Is this unusual only for Alice, or unusual for managers generally?

---

# 17. Robust Baseline Statistics

Do not depend only on averages.

Use:

- Median
- Quantiles
- Median Absolute Deviation
- Trimmed distributions
- Long-term trusted windows

Example:

```text
Normal report access:

median = 18/day
P90 = 27/day
P99 = 43/day
```

A current count of 300 is much easier to interpret than a raw mean deviation alone.

---

# 18. Baseline Poisoning Protection

Attackers may gradually normalize bad behavior.

Example:

```text
Week 1: 20 files
Week 2: 23
Week 3: 27
Week 4: 34
Week 5: 41
Week 6: 50
```

Without safeguards, 50 may become "normal."

Use:

```text
if risk < 30:
    full baseline update

elif 30 <= risk <= 50:
    reduced baseline update

else:
    no baseline update
```

Also calculate drift:

```text
trusted baseline
vs
recent baseline
```

If drift is unusually fast:

```text
BASELINE_DRIFT_WARNING
```

---

# 19. ML Anomaly Model

## V1 model

Use:

```text
Isolation Forest
```

Reason:

- Does not require large labeled malicious datasets
- Good for anomaly-style prototypes
- Fast to train
- Easy to integrate
- Good enough to demonstrate the concept

Input:

```text
feature vector
```

Output:

```text
anomaly score 0.0â€“1.0
```

Do not treat:

```text
anomaly = 0.91
```

as:

```text
91% chance of attacker
```

It means the behavior is highly unusual relative to the learned distribution.

---

# 20. Sequence Detection

Risk decay alone is vulnerable to low-and-slow attacks.

Track event transitions.

Example normal sequence:

```text
LOGIN
â†’ DASHBOARD
â†’ REPORT
â†’ LOGOUT
```

Suspicious sequence:

```text
LOGIN
â†’ SERVER_DISCOVERY
â†’ REMOTE_ACCESS
â†’ ADMIN_RESOURCE
â†’ CREDENTIAL_RESOURCE
â†’ EXPORT
```

Implement V1 using:

- Event n-grams
- Transition probabilities
- Small Markov-style transition matrix

Example:

```text
P(REPORT | LOGIN) = high
P(DASHBOARD | LOGIN) = high
P(SCAN | LOGIN) = low
P(CREDENTIAL_RESOURCE | SCAN) = extremely low
```

Rare sequences increase sequence risk even if individual events are mild.

---

# 21. Rule Engine

Rules provide explicit evidence.

Example rules:

```text
IF failed_logins > threshold
THEN rule += AUTH_FAILURE_BURST
```

```text
IF current_device not in known_devices
THEN rule += NEW_DEVICE_CONTEXT
```

```text
IF unique_targets > peer_p99
THEN rule += TARGET_ENUMERATION
```

```text
IF privileged_resource_access AND personal_baseline_rare
THEN rule += PRIVILEGE_CONTEXT_ANOMALY
```

```text
IF concurrent_sessions >= 2 AND devices_different
THEN rule += CONCURRENT_SESSION_ANOMALY
```

Rules are not "AI." They are explicit security evidence.

---

# 22. Intent Classification

V1 should be deterministic and explainable.

Possible classes:

```text
NONE
RECON
CREDENTIAL_HUNTING
LATERAL_MOVEMENT
PRIVILEGE_ESCALATION
DATA_COLLECTION
EXFIL_ATTEMPT
```

Example:

```text
multiple new hosts
+
repeated remote access attempts
+
unusual service targeting

â†’ LATERAL_MOVEMENT
```

Example:

```text
admin resource discovery
+
credential-related resource access
+
explicit credential events

â†’ CREDENTIAL_HUNTING
```

Example:

```text
sensitive data reads
+
large access volume
+
export endpoint

â†’ EXFIL_ATTEMPT
```

Output:

```json
{
  "intent": "CREDENTIAL_HUNTING",
  "confidence": 0.91
}
```

---

# 23. Risk Engine

Do not use a single ML score.

Maintain separate components:

```text
Behavioral Anomaly
Peer Deviation
Identity/Device Context
Sequence Risk
Rule Evidence
Resource Sensitivity
Intent Confidence
Decoy Evidence
Legitimate Context
```

Example:

```text
Behavior anomaly      82
Peer deviation        71
Device/context        75
Sequence risk         89
Resource sensitivity  70
Rule evidence         78
```

Then calculate a final normalized session risk.

Conceptually:

```text
risk =
    behavioral_component
  + sequence_component
  + context_component
  + resource_component
  + rule_component
  + deception_component
  - verified_legitimate_context
```

Do not claim fixed weights are scientifically optimal.

For the prototype they are configurable and later calibrated from validation data.

---

# 24. Risk Levels

Suggested initial values:

```text
0â€“30
NORMAL

31â€“50
ELEVATED

51â€“74
HIGH

75â€“89
CRITICAL-CANDIDATE

90â€“100
CRITICAL
```

Exact numbers are configurable.

---

# 25. Response Ladder

Avoid immediately blocking identities.

## Normal

```text
Continue monitoring
```

## Elevated

```text
Increase context collection
Show analyst warning
```

## High

```text
Require additional verification for sensitive actions
Increase telemetry
Mark session for investigation
```

## Critical Candidate

If:

```text
high risk
+
attack intent
```

then:

```text
deception may become eligible
```

## Critical

If additional high-confidence evidence appears:

```text
revoke suspicious session
restrict protected operations
alert SOC
```

## Full account disablement

Must remain analyst-approved in the prototype design.

---

# 26. Deception Decision Logic

Never:

```text
risk > 75 â†’ decoy
```

Use:

```python
DECEPTION_ALLOWED = (
    session.risk >= HIGH_THRESHOLD
    and session.intent in {
        "RECON",
        "CREDENTIAL_HUNTING",
        "LATERAL_MOVEMENT",
        "EXFIL_ATTEMPT",
    }
    and session.intent_confidence >= INTENT_THRESHOLD
    and not session.has_strong_legitimate_override
)
```

This prevents a deadline-day bulk operation from automatically being redirected to fake data.

---

# 27. Controlled Corporate Application

The easiest safe prototype is a controlled internal application.

Example:

```text
http://corp.internal
```

Modules:

- Dashboard
- Reports
- Finance
- Customer Database
- Admin
- Credentials
- Export

Every sensitive request passes through:

```text
Browser
   â†“
Policy Gateway
   â†“
Real or Decoy
```

The detector therefore has a real enforcement point.

---

# 28. Decoy Architecture

Do not try to transparently replace every Windows service in V1.

Build a controlled decoy service.

Example fake paths:

```text
/admin
/admin/users
/admin/credentials
/database/customers
/database/payroll
/files/confidential
/export
```

Use synthetic data only.

Example:

```text
Finance_2026/
â”œâ”€â”€ Forecast_Q1.xlsx
â”œâ”€â”€ Forecast_Q2.xlsx
â”œâ”€â”€ Acquisitions/
â”‚   â””â”€â”€ confidential_target.csv
â””â”€â”€ Credentials/
    â””â”€â”€ legacy-service.json
```

---

# 29. Decoy Realism

Static honeypots can be fingerprinted.

Improve realism with:

- Plausible directory names
- Consistent timestamps
- Consistent file sizes
- Realistic object relationships
- Realistic application banners
- Simulated request latency
- Background log entries
- Plausible fake usernames
- Plausible fake service names

Never expose real confidential data inside the deception environment.

---

# 30. Decoy Evidence

A decoy interaction should not alone prove malicious intent.

Use:

```text
prior high-risk context
+
attack intent
+
decoy interaction
```

Example:

```text
Risk before decoy = 82

Intent = Credential Hunting
Confidence = 0.91

Fake credential accessed
Fake credential attempted

Risk = 97
```

This becomes a strong containment signal.

---

# 31. Session Containment

Prototype containment:

```text
invalidate the suspicious application session
```

Do not automatically disable the AD account.

Example:

```text
Alice

Session S18 / MGR-PC
Risk 8
ACTIVE

Session S92 / EMP-PC
Risk 97
CONTAINED
```

This demonstrates that legitimate work remains unaffected.

---

# 32. Database Design

Recommended tables:

## identities

```text
id
pseudonymous_id
role_id
department_id
created_at
```

## devices

```text
id
device_name
device_hash
assigned_identity_id
first_seen
last_seen
```

## sessions

```text
id
identity_id
device_id
started_at
last_seen
risk_score
anomaly_score
sequence_score
intent
intent_confidence
status
```

## events

```text
id
timestamp
session_id
identity_id
device_id
event_type
category
source
target
resource_type
sensitivity
result
metadata_json
```

## baseline_profiles

```text
identity_id
feature_name
median
p90
p99
mad
updated_at
```

## peer_baselines

```text
role_id
feature_name
median
p90
p99
mad
updated_at
```

## risk_snapshots

```text
id
session_id
timestamp
behavior_score
peer_score
sequence_score
context_score
resource_score
rule_score
intent_score
final_risk
```

## intent_detections

```text
id
session_id
timestamp
intent
confidence
evidence_json
```

## decoy_interactions

```text
id
session_id
timestamp
resource
action
evidence_json
```

## response_actions

```text
id
session_id
timestamp
action_type
reason
automated
status
```

## approvals

```text
id
identity_id
session_id
approval_type
valid_from
valid_until
approved_by
```

---

# 33. Backend API Design

Base:

```text
/api/v1
```

## Overview

```text
GET /overview
GET /risk/activity
```

## Sessions

```text
GET /sessions
GET /sessions/{id}
GET /sessions/{id}/timeline
GET /sessions/{id}/risk
GET /sessions/{id}/features
POST /sessions/{id}/contain
```

## Identities

```text
GET /identities
GET /identities/{id}
GET /identities/{id}/sessions
GET /identities/{id}/baseline
```

## Events

```text
GET /events
GET /events/live
```

## Incidents

```text
GET /incidents
GET /incidents/{id}
```

## Deception

```text
GET /deception/sessions
GET /deception/interactions
```

## Simulation

```text
POST /simulation/run
POST /simulation/reset
GET /simulation/scenarios
```

## WebSocket

```text
/ws/events
/ws/risk
/ws/incidents
```

---

# 34. Recommended Repository Structure

```text
CyberBug/
â”‚
â”œâ”€â”€ backend/
â”‚   â”œâ”€â”€ app/
â”‚   â”‚   â”œâ”€â”€ main.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ collector/
â”‚   â”‚   â”‚   â”œâ”€â”€ windows_events.py
â”‚   â”‚   â”‚   â”œâ”€â”€ forwarded_events.py
â”‚   â”‚   â”‚   â””â”€â”€ parser.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ normalization/
â”‚   â”‚   â”‚   â””â”€â”€ event.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ privacy/
â”‚   â”‚   â”‚   â”œâ”€â”€ pseudonymizer.py
â”‚   â”‚   â”‚   â””â”€â”€ sanitizer.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ sessions/
â”‚   â”‚   â”‚   â”œâ”€â”€ correlator.py
â”‚   â”‚   â”‚   â””â”€â”€ drift.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ features/
â”‚   â”‚   â”‚   â”œâ”€â”€ extractor.py
â”‚   â”‚   â”‚   â””â”€â”€ rolling.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ baseline/
â”‚   â”‚   â”‚   â”œâ”€â”€ personal.py
â”‚   â”‚   â”‚   â”œâ”€â”€ peer.py
â”‚   â”‚   â”‚   â”œâ”€â”€ robust_stats.py
â”‚   â”‚   â”‚   â””â”€â”€ poisoning_guard.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ ml/
â”‚   â”‚   â”‚   â”œâ”€â”€ isolation_forest.py
â”‚   â”‚   â”‚   â”œâ”€â”€ train.py
â”‚   â”‚   â”‚   â””â”€â”€ inference.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ detection/
â”‚   â”‚   â”‚   â”œâ”€â”€ rules.py
â”‚   â”‚   â”‚   â”œâ”€â”€ sequence.py
â”‚   â”‚   â”‚   â””â”€â”€ intent.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ risk/
â”‚   â”‚   â”‚   â”œâ”€â”€ engine.py
â”‚   â”‚   â”‚   â””â”€â”€ thresholds.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ policy/
â”‚   â”‚   â”‚   â”œâ”€â”€ engine.py
â”‚   â”‚   â”‚   â””â”€â”€ overrides.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ deception/
â”‚   â”‚   â”‚   â”œâ”€â”€ router.py
â”‚   â”‚   â”‚   â”œâ”€â”€ decoy_data.py
â”‚   â”‚   â”‚   â””â”€â”€ evidence.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ containment/
â”‚   â”‚   â”‚   â””â”€â”€ session.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ simulation/
â”‚   â”‚   â”‚   â”œâ”€â”€ normal.py
â”‚   â”‚   â”‚   â”œâ”€â”€ deadline.py
â”‚   â”‚   â”‚   â”œâ”€â”€ stolen_credentials.py
â”‚   â”‚   â”‚   â”œâ”€â”€ session_hijack.py
â”‚   â”‚   â”‚   â””â”€â”€ low_and_slow.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ api/
â”‚   â”‚   â”‚   â”œâ”€â”€ overview.py
â”‚   â”‚   â”‚   â”œâ”€â”€ sessions.py
â”‚   â”‚   â”‚   â”œâ”€â”€ identities.py
â”‚   â”‚   â”‚   â”œâ”€â”€ incidents.py
â”‚   â”‚   â”‚   â”œâ”€â”€ deception.py
â”‚   â”‚   â”‚   â””â”€â”€ websocket.py
â”‚   â”‚   â”‚
â”‚   â”‚   â”œâ”€â”€ db/
â”‚   â”‚   â”‚   â”œâ”€â”€ models.py
â”‚   â”‚   â”‚   â”œâ”€â”€ session.py
â”‚   â”‚   â”‚   â””â”€â”€ migrations/
â”‚   â”‚   â”‚
â”‚   â”‚   â””â”€â”€ config.py
â”‚   â”‚
â”‚   â”œâ”€â”€ tests/
â”‚   â”œâ”€â”€ models/
â”‚   â”œâ”€â”€ requirements.txt
â”‚   â””â”€â”€ pyproject.toml
â”‚
â”œâ”€â”€ frontend/
â”‚   â”œâ”€â”€ src/
â”‚   â”‚   â”œâ”€â”€ routes/
â”‚   â”‚   â”œâ”€â”€ components/
â”‚   â”‚   â”œâ”€â”€ features/
â”‚   â”‚   â”‚   â”œâ”€â”€ overview/
â”‚   â”‚   â”‚   â”œâ”€â”€ sessions/
â”‚   â”‚   â”‚   â”œâ”€â”€ identities/
â”‚   â”‚   â”‚   â”œâ”€â”€ incidents/
â”‚   â”‚   â”‚   â”œâ”€â”€ telemetry/
â”‚   â”‚   â”‚   â”œâ”€â”€ deception/
â”‚   â”‚   â”‚   â””â”€â”€ simulation/
â”‚   â”‚   â”œâ”€â”€ api/
â”‚   â”‚   â””â”€â”€ styles/
â”‚   â””â”€â”€ package.json
â”‚
â”œâ”€â”€ docs/
â”‚   â”œâ”€â”€ architecture.md
â”‚   â”œâ”€â”€ threat-model.md
â”‚   â””â”€â”€ demo-script.md
â”‚
â””â”€â”€ README.md
```

---

# 35. Frontend Architecture

Use:

```text
React
+
TypeScript
+
Vite
+
TanStack Router
+
TanStack Query
+
TanStack Table
+
shadcn/ui
+
Tailwind CSS
+
Recharts
```

Do not use TanStack Start unless server-side React features are genuinely needed. The backend is already FastAPI.

---

# 36. UI/UX Direction

The UI should look like a **professional SOC / enterprise security console**.

Avoid:

- Neon hacker aesthetics
- Matrix backgrounds
- Giant glowing gauges
- Excessive gradients
- Huge Material-style cards
- Consumer-app appearance
- Too much whitespace
- Too many charts

Use:

- Dark neutral background
- Dense but readable layout
- Subtle borders
- Small/medium radius
- Strong table design
- Clear status badges
- Excellent typography
- Minimal shadows
- Explainable evidence panels
- Timelines
- Compact charts
- Monospace only for technical values

---

# 37. Material 3 Decision

Use Material principles selectively:

- Predictable interaction states
- Accessibility
- Hierarchy
- Spacing consistency
- Strong component states

Do **not** use pure Material 3 visual styling.

A SOC tool needs denser information and stronger analytical presentation.

Recommended:

```text
shadcn/ui
+
custom SOC design system
```

Visual inspiration:

- Microsoft Sentinel
- CrowdStrike
- Sentry
- Datadog
- Grafana
- Linear

---

# 38. Main Navigation

```text
Overview

Investigate
â”œâ”€â”€ Sessions
â”œâ”€â”€ Identities
â””â”€â”€ Incidents

Monitor
â”œâ”€â”€ Live Telemetry
â””â”€â”€ Baselines

Deception
â”œâ”€â”€ Active Decoys
â””â”€â”€ Interactions

Manage
â”œâ”€â”€ Policies
â””â”€â”€ Settings

Simulation
```

---

# 39. Overview Screen

Main purpose:

> What needs attention right now?

Suggested structure:

```text
Security Overview                        LIVE â—

Active Sessions     Elevated     Critical
126                 8            2


Risk Activity â€” Last 24h

[compact time-series chart]


Sessions Requiring Attention

Identity   Device   Risk   Intent              Status
USR-A12    EMP-PC   94     Credential Hunting  Contained
USR-B91    PC-08    76     Recon               Investigate
USR-C18    PC-14    63     Unknown             Elevated
```

---

# 40. Session Investigation Screen

This is the most important screen.

```text
Session SES-A817                         CRITICAL 94

USR-A12 / EMP-PC-22
Started 02:31:08

[Contain Session]


WHY THIS SESSION IS RISKY

Device context deviation        High
Unseen server access            9 hosts
SSH deviation                   8.2Ã— baseline
Privilege-resource attempts     4
Sequence anomaly                0.89


Probable Intent

Credential Hunting
Confidence: 91%


TIMELINE

02:31   Successful authentication
02:33   New resource
02:35   Server enumeration
02:36   Remote access attempts
02:38   Admin-resource discovery
02:41   Credential-hunting pattern
02:42   Deception eligible
02:43   Honey credential accessed
02:44   Session contained
```

---

# 41. Behavioral Comparison UX

Show:

```text
SESSION VS NORMAL

                       Normal   Current

Target systems             3       14
Failed logins              0        8
Admin resources            1        6
Sensitive reads           12      173
Concurrent devices         1        2
```

This helps judges understand what the ML is actually comparing.

---

# 42. Identity Screen

Never label the person permanently as malicious.

```text
Identity USR-A12

Normal sessions      143
Elevated sessions      3
Contained sessions     1


Active Sessions

MGR-PC       Risk 8      Normal
EMP-PC       Risk 94     Contained
```

---

# 43. Deception Screen

```text
Deception

Active Decoy Sessions: 1


SES-A817

Intent:
Credential Hunting

Entered deception:
02:42:18


02:42:18   /admin
02:42:22   /admin/credentials
02:42:35   service-prod.json
02:42:42   honey credential copied
02:43:02   honey credential attempted
02:44:11   session contained


Real Resource

Never Exposed âœ“
```

---

# 44. Incident Screen

```text
INC-0024

Potential compromised privileged identity

Severity:
CRITICAL


Evidence

âœ“ Behavioral anomaly
âœ“ Device-context anomaly
âœ“ Rare attack sequence
âœ“ Credential-hunting intent
âœ“ Decoy interaction


Affected Identity
USR-A12

Affected Session
SES-A817

Response
Session revoked
Account still active
Legitimate session unaffected
```

---

# 45. Live Telemetry Screen

```text
LIVE EVENTS                                      â— LIVE

03:02:18 AUTH_SUCCESS      USR-A12 EMP-PC   success
03:02:22 RESOURCE_ACCESS   USR-A12 FIN-01   success
03:02:27 SERVER_DISCOVERY  USR-A12 CORP-NET
03:02:29 AUTH_FAILURE      USR-A12 SRV-07   failed
03:02:31 AUTH_FAILURE      USR-A12 SRV-08   failed
03:02:33 RISK_CHANGED      SES-A817 42 â†’ 58
```

---

# 46. Simulation Screen

Hackathon-safe deterministic scenarios:

```text
Simulation Lab

â—‹ Normal manager activity
â—‹ Deadline bulk operation
â—‹ Stolen credential attack
â—‹ Session hijack
â—‹ Low-and-slow attack

[Run Scenario]
```

The selected scenario generates synthetic security events through the same backend pipeline.

The dashboard reacts live.

---

# 47. Required Demo Scenarios

## Scenario A â€” Normal Employee

Expected:

```text
Low anomaly
Low risk
No alert
No deception
```

---

## Scenario B â€” Deadline-Day Legitimate Bulk Operation

Example:

```text
11 PM
large number of report downloads
new repository access
```

Expected:

```text
Anomaly increases
Risk may increase

BUT

approved work context exists

â†’ no deception
â†’ no hard block
```

This proves false-positive resistance.

---

## Scenario C â€” Stolen Credentials

Expected flow:

```text
Manager credentials
        â†“
EMP-PC login
        â†“
new device context
        â†“
risk rises slightly
        â†“
server discovery
        â†“
remote-access attempts
        â†“
admin-resource discovery
        â†“
credential hunting
        â†“
high risk + intent
        â†“
decoy resource
        â†“
honey credential interaction
        â†“
session containment
```

---

## Scenario D â€” Session Hijack

Same:

```text
user
device
session
```

but behavior changes sharply in the same session.

Expected:

```text
within-session drift increases
sequence score increases
risk increases
```

This proves the design does not depend entirely on having a second session.

---

## Scenario E â€” Low-and-Slow

Example:

```text
small suspicious event
wait
small suspicious event
wait
repeat
```

Expected:

```text
instantaneous score may decay

BUT

sequence memory remains

â†’ rare attack progression accumulates
```

This proves resistance to threshold gaming.

---

# 48. Complete Demo Story

Recommended judge-facing flow:

```text
1. Alice works normally on MGR-PC.
   Risk = 8.

2. Bob uses Alice's credentials on EMP-PC.

3. Login succeeds because credentials are valid.

4. Device/context mismatch appears.
   Risk 8 â†’ 27.

5. No blocking occurs.

6. Bob begins server discovery.

7. ML anomaly score rises.

8. Sequence engine observes:
   LOGIN â†’ DISCOVERY â†’ REMOTE ACCESS â†’ ADMIN

9. Risk 27 â†’ 68.

10. Still no deception.

11. Bob begins credential-hunting activity.

12. Intent engine:
    CREDENTIAL_HUNTING
    Confidence 0.91

13. Risk = 82.
    Intent condition is satisfied.
    No legitimate override exists.

14. Policy engine exposes a controlled fake credential resource.

15. Bob opens/copies the honey credential.

16. Decoy evidence raises confidence.

17. Risk 82 â†’ 97.

18. Suspicious session is revoked.

19. Alice's legitimate MGR-PC session remains active.

20. Dashboard shows the full timeline and explanation.
```

---

# 49. Why This Demo Is Strong

It demonstrates:

- Valid credentials can still be dangerous
- Authentication alone is not enough
- The system does not automatically accuse users
- Sessions are evaluated separately
- Same-session hijacking is considered
- Baseline poisoning is addressed
- Peer-group behavior is considered
- Low-and-slow attacks are considered
- High risk does not automatically trigger deception
- Deception requires attack intent
- Legitimate context can veto deception
- Containment is session-scoped
- Analysts get explainable evidence

---

# 50. Implementation Phases

## Phase 1 â€” Foundation

Build:

- FastAPI project
- SQLite/PostgreSQL connection
- Pydantic schemas
- Event model
- Session model
- Basic React UI
- WebSocket connection

Goal:

```text
backend â†” frontend works
```

---

## Phase 2 â€” Simulation First

Build event simulator before Windows integration.

Scenarios:

- Normal
- Deadline
- Stolen credentials
- Session hijack
- Low-and-slow

Goal:

```text
synthetic event
    â†“
backend
    â†“
database
    â†“
live dashboard
```

---

## Phase 3 â€” Session Correlation

Implement:

```text
identity Ã— session Ã— device-context
```

Add:

- Session creation
- Session updating
- Concurrent session detection
- Device context

Goal:

```text
multiple sessions for same identity
```

---

## Phase 4 â€” Feature Engine

Implement rolling feature windows.

Start with:

- Failed logins
- New targets
- Resource counts
- Admin attempts
- Sensitive access
- Concurrent sessions
- Device novelty
- Time-of-day deviation

---

## Phase 5 â€” Baselines

Implement:

- Personal baseline
- Peer baseline
- Robust statistics
- Baseline update freezing
- Drift detection

---

## Phase 6 â€” ML

Train Isolation Forest on:

- Simulated normal activity
- Optional public benchmark-derived features

Output:

```text
anomaly score
```

Do not make ML responsible for the final security decision.

---

## Phase 7 â€” Rule Engine

Implement deterministic evidence:

- Failed authentication burst
- New device
- New target burst
- Privileged-resource access
- Sensitive-access burst
- Concurrent session

---

## Phase 8 â€” Sequence Engine

Implement n-gram / transition tracking.

Score rare event sequences.

---

## Phase 9 â€” Intent Engine

Implement:

- RECON
- CREDENTIAL_HUNTING
- LATERAL_MOVEMENT
- EXFIL_ATTEMPT

Return:

```text
intent
confidence
evidence
```

---

## Phase 10 â€” Risk Engine

Combine:

- ML anomaly
- Personal deviation
- Peer deviation
- Device/context
- Rules
- Sequence
- Resource sensitivity
- Legitimate overrides

Generate:

```text
risk 0â€“100
```

Store every risk transition.

---

## Phase 11 â€” Controlled Corporate App

Create real and protected resources.

Every sensitive request goes through policy evaluation.

---

## Phase 12 â€” Deception

Implement static synthetic decoys.

Route only:

```text
high risk
+
attack intent
+
no strong legitimate override
```

---

## Phase 13 â€” Containment

Implement:

```text
application session revocation
```

Do not automatically disable Windows accounts.

---

## Phase 14 â€” Windows Event Integration

Start with local Windows Security logs.

Then:

```text
MGR-PC
EMP-PC
CORP-SRV
    â†“
WEF
    â†“
SEC-SRV
```

Parse into the same normalized schema used by the simulator.

This allows the simulation and live Windows prototype to share the entire detection pipeline.

---

# 51. Testing Strategy

## Unit Tests

Test:

- Event normalization
- Pseudonymization
- Feature extraction
- Baseline updates
- Poisoning protection
- Rule detection
- Sequence scoring
- Intent classification
- Risk scoring
- Deception gating

---

## Integration Tests

Test:

```text
event
â†“
session
â†“
features
â†“
risk
â†“
intent
â†“
policy
```

---

## False-Positive Tests

Critical test:

```text
deadline-day legitimate bulk activity
```

Expected:

```text
high anomaly possible
BUT
no malicious intent
OR
strong legitimate override

â†’ no deception
```

---

## Session Hijack Tests

Expected:

```text
same identity
same device
same session

behavior changes sharply

â†’ within-session drift triggers
```

---

## Baseline Poisoning Tests

Feed gradually increasing suspicious behavior.

Expected:

```text
baseline learning slows/freezes
drift warning appears
```

---

## Low-and-Slow Tests

Expected:

```text
instant score may fall
sequence memory remains
attack progression still detected
```

---

# 52. Evaluation Metrics

Do not use accuracy alone.

Track:

- Precision
- Recall
- PR-AUC
- False positives per 1,000 user-days
- False containment rate
- Detection delay
- Time to containment
- Number of analyst alerts
- Percentage of alerts with explainable evidence

For the hackathon, the most meaningful qualitative metric is:

> Can the system detect malicious progression while allowing a legitimate deadline-day anomaly to continue without deception?

---

# 53. Security and Safety Constraints

The prototype must ensure:

- Decoy data is synthetic
- Decoy environment cannot access production data
- Session containment is reversible
- Full account block is not automatic
- Identity mappings are restricted
- Raw logs have limited retention
- Sensitive personal data is minimized
- Simulation is isolated from real external systems
- No uncontrolled exploitation is required for demo

---

# 54. Known Limitations

The prototype must be honest about limitations.

## Attribution

The system can detect behavioral inconsistency.

It cannot always prove which physical person is at the keyboard.

---

## Agentless Visibility

WEF and Windows audit logs only expose events Windows is configured to generate.

Without Sysmon/EDR, process-level visibility is limited.

---

## Honeypot Coverage

The prototype can only redirect resources behind a controlled enforcement point.

It cannot magically redirect arbitrary Windows services.

---

## ML

Isolation Forest detects unusual behavior, not malicious intent.

Intent and response therefore depend on additional evidence.

---

## New Users

New employees have little historical data.

Peer-group baselines must carry more weight initially.

---

# 55. Future Production Evolution

After the Windows prototype works:

## Phase A

Add:

- Microsoft Entra / identity-provider logs
- VPN logs
- Firewall logs
- Database audit logs
- SaaS access logs

## Phase B

Add:

- Linux collectors
- macOS telemetry
- Common OCSF-style schema
- Cross-platform normalization

## Phase C

Add:

- Kafka/Redpanda
- ClickHouse
- Dedicated model serving
- Policy Enforcement integrations
- PAM integration
- Step-up authentication
- Token revocation
- EDR integrations

## Phase D

Add:

- More sophisticated sequence models
- Graph-based identity/resource modeling
- Calibrated risk models
- Online drift detection
- Analyst feedback loop

---

# 56. Final Technology Decision

For the first prototype:

```text
Operating System
Windows only

Telemetry
Windows Security Logs
WEF / WEC
Optional Sysmon

Backend
Python
FastAPI
asyncio
pywin32
Pydantic

ML
NumPy
Pandas
SciPy
scikit-learn
Isolation Forest

Database
SQLite initially
PostgreSQL for final demo
SQLAlchemy
Alembic

Frontend
React
TypeScript
Vite
TanStack Router
TanStack Query
TanStack Table
shadcn/ui
Tailwind CSS
Recharts

Real-time
FastAPI WebSockets

Testing
pytest
```

---

# 57. Final Architecture Principle

The system should always be presented as:

```text
PREVENT
   â†“
OBSERVE
   â†“
MODEL
   â†“
CORRELATE
   â†“
SCORE
   â†“
VERIFY INTENT
   â†“
DECEIVE WHEN SAFE
   â†“
CONTAIN THE SUSPICIOUS SESSION
```

Not:

```text
High ML score
   â†“
Honeypot
   â†“
Block employee
```

---

# 58. One-Minute Project Explanation

> CyberBug is a privacy-conscious Windows security prototype for detecting insider threats and compromised employee accounts even when valid credentials are being used. Windows security telemetry is collected through native event logging and Windows Event Forwarding, normalized, pseudonymized, and correlated into user-session-device contexts. The system learns both personal and role-based behavior, uses Isolation Forest and robust statistical baselines to detect anomalies, and adds sequence analysis and explainable security rules to identify suspicious progression. A high anomaly score alone never triggers deception. The system first requires high contextual risk and evidence of an attack intent such as reconnaissance, credential hunting, lateral movement, or exfiltration. Only then can selected protected resources expose isolated synthetic decoys. If the suspicious context interacts with those decoys, confidence increases and only that session is contained, while legitimate sessions remain unaffected.

---

# 59. Prototype Success Criteria

The prototype is successful when it can demonstrate all of the following in one flow:

1. Normal manager behavior remains low risk.
2. Valid manager credentials can successfully authenticate from another corporate PC.
3. The system does not immediately block or accuse the user.
4. Risk grows as behavior deviates.
5. Personal and peer baselines contribute to the decision.
6. Suspicious data is prevented from poisoning the baseline.
7. Rare event sequences increase risk even during low-and-slow attacks.
8. Deadline-day legitimate bulk work does not automatically trigger deception.
9. Deception requires both high risk and attack intent.
10. Decoy interaction is captured as additional evidence.
11. Only the suspicious session is contained.
12. The legitimate manager session remains active.
13. The dashboard explains exactly why every risk increase occurred.

---

# 60. Recommended Build Priority

If time is limited, build in this order:

```text
1. Event simulator
2. FastAPI + database
3. Session model
4. Live dashboard
5. Feature extraction
6. Personal baseline
7. Peer baseline
8. Risk engine
9. Isolation Forest
10. Rule engine
11. Sequence engine
12. Intent classifier
13. Controlled corporate app
14. Deception routing
15. Session containment
16. Windows Event Log integration
17. WEF multi-machine setup
18. Optional Sysmon
19. UI polish
20. Demo script + pitch
```

The reason simulation comes first is that the full security pipeline can be built and debugged independently of Windows event-collection issues. Once the logic works, real Windows events can be mapped into the exact same normalized event format.

---

# 61. Final Recommendation

For the hackathon, do not attempt to build a complete enterprise security product.

Build one highly convincing end-to-end Windows scenario:

```text
Normal Manager
      â†“
Stolen Credentials
      â†“
Valid Login
      â†“
Behavioral Drift
      â†“
Explainable Risk Growth
      â†“
Attack Intent
      â†“
Controlled Decoy
      â†“
Additional Evidence
      â†“
Suspicious Session Containment
      â†“
Legitimate Session Continues
```

That single scenario demonstrates the project's strongest technical ideas without overclaiming what the prototype can do.

