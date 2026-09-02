# CyberBug — Stage 1 architecture

```text
Synthetic scenario state
        ↓
FastAPI typed API
        ↓
React SOC console
        ↓
Analyst session investigation
```

The frontend never decides whether to expose a decoy or contain a session. It renders server-provided session state and calls an explicit session-only containment action. Future detection services will populate the same API contracts.

## Decision ownership

| Concern | Current location | Later replacement |
| --- | --- | --- |
| Session state | `app.simulation.store` | SQLAlchemy repository |
| Risk and intent values | safe scenario fixtures | risk + intent engine |
| Evidence timeline | safe scenario fixtures | normalized security events |
| UI containment control | `SessionPanel` | same UI, audited response service |

No current code claims Windows logs provide complete endpoint visibility, or that a high anomaly proves a person is malicious.
