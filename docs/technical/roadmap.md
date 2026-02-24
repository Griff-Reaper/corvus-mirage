# Corvus Mirage — Technical Roadmap

> *"The raven watches everything. The mirage is what the attacker sees."*

**Version:** 0.3 — Red Team Complete  
**Started:** February 21, 2026  
**Last Updated:** February 24, 2026  
**Status:** Active Development

---

## Platform Overview

Corvus Mirage is a three-component AI security platform targeting two attack surfaces that existing tools leave unprotected: AI systems themselves (prompt injection, jailbreaks, adversarial inputs) and the humans who operate them (vishing, social engineering, pretexting).

The result is a complete offensive-defensive loop:

```
ARIA          — detects attacks against humans (voice/vishing layer)
Gateway       — detects attacks against AI systems (prompt protection layer)
Red Team      — proves both work (continuous validation engine)
```

---

## Build Status

### ✅ Phase 1 — Foundation (Day 1 · Feb 21)
- [x] Monorepo structure established
- [x] Shared config layer (`shared/config.py`)
- [x] Shared threat intelligence database (`shared/threat_intel_init.py`)
- [x] Shared alerting pipeline (`shared/alerting.py`)
- [x] Shared event bus for cross-component communication
- [x] Platform documentation initialized
- [x] Dev journal started
- [x] Domain secured (corvusmirage.ai)
- [x] GitHub repo initialized

### ✅ Phase 2 — ARIA Voice Layer (Day 1 · Feb 21)
- [x] Twilio webhook handler (`/incoming`)
- [x] Deepgram real-time streaming (`/voice/stream/{session_id}`)
- [x] Claude detection engine (`core/detection_engine.py`)
- [x] Session management and active session tracking
- [x] WebSocket manager for dashboard real-time updates
- [x] Threat intel write-back on detection
- [x] Alert pipeline integration (Slack webhook)
- [x] Full pipeline validated: live call → STT → AI detection → alert
- [x] Direct transcript endpoint for red team (`/analyze-transcript`)

### ✅ Phase 3 — Gateway AI Protection Layer (Day 2 · Feb 22)
- [x] FastAPI prompt inspection endpoint (`POST /inspect`)
- [x] Three-layer ensemble detection engine
  - [x] Rule-based detector (40% weight) — pattern matching
  - [x] Statistical detector (25% weight) — anomaly detection
  - [x] Semantic detector (35% weight) — intent analysis
- [x] Policy engine with configurable rulesets
- [x] Sanitizer for SANITIZE action (strip vs. block)
- [x] Admin policy management API (`/admin/policies`)
- [x] WebSocket broadcast for dashboard events
- [x] Shared threat intel integration
- [x] Detection engine v1.1 — red team tuned (87.3% coverage)

### ✅ Phase 4 — Red Team Simulator (Day 3 · Feb 24)
- [x] Attack library: 55 attacks across 5 categories
  - [x] Prompt Injection (16 attacks)
  - [x] Jailbreak (12 attacks)
  - [x] Role Manipulation (8 attacks)
  - [x] Encoding Tricks (8 attacks)
  - [x] Vishing Scripts (11 attacks)
- [x] Async attack runner with health checks
- [x] Per-attack classification: DETECTED / BLOCKED / MISSED / ERROR
- [x] Coverage scorer with severity weighting
- [x] JSON + text report generation
- [x] Single command entry point with CLI flags
- [x] CI-ready exit codes

**Current Benchmark: 48/55 (87.3%) — PITCH READY**
```
Prompt Injection    12/16   ( 75.0%)
Jailbreak           12/12   (100.0%)
Role Manipulation    8/8    (100.0%)
Encoding Trick       5/8    ( 62.5%)
Vishing Script      11/11   (100.0%)
```

### 🔲 Phase 5 — Unified Dashboard (Upcoming)
- [ ] React frontend scaffold
- [ ] ARIA live session panel (active calls, transcripts, threat scores)
- [ ] Gateway event feed (inspections, blocks, threat levels)
- [ ] Red Team coverage widget (last run scores, trend over time)
- [ ] Unified threat timeline (cross-component events in chronological order)
- [ ] Alert history and acknowledgment
- [ ] WebSocket connections to ARIA (:8001) and Gateway (:8002)

### 🔲 Phase 6 — Intelligence Integration (Upcoming)
- [ ] Cross-component threat correlation (ARIA session + Gateway event same attacker)
- [ ] Threat pattern learning (detected techniques inform future detection)
- [ ] Geolocation enrichment from Twilio metadata
- [ ] IOC feed integration
- [ ] Attacker session fingerprinting

### 🔲 Phase 7 — Production Hardening (Pre-Pitch)
- [ ] Docker Compose full-stack deployment
- [ ] Environment-based config (dev / staging / prod)
- [ ] Rate limiting on all public endpoints
- [ ] Authentication layer for admin routes
- [ ] Red team scheduled runs (nightly CI)
- [ ] Coverage delta tracking (compare runs, surface regressions)
- [ ] Attack library versioning and changelog

### 🔲 Phase 8 — Pitch Preparation
- [ ] Demo environment setup (stable, reproducible)
- [ ] Benchmark documentation (methodology, attack library, scoring)
- [ ] Landing page (corvusmirage.ai via Cloudflare Pages)
- [ ] One-page pitch deck
- [ ] Technical writeup: "How we caught 87.3% of known AI attacks"

---

## Known Gaps (Documented, Not Failures)

The following 7 attacks currently evade detection. They are tracked here as roadmap items:

| ID | Category | Description | Why It's Hard |
|----|----------|-------------|---------------|
| pi_004 | Prompt Injection | XML tag injection spoofing assistant turn | Requires understanding XML structure, not just patterns |
| pi_006 | Prompt Injection | Benign question + appended system update | Low-signal — looks like normal user input until the append |
| pi_009 | Prompt Injection | False context establishment | Requires multi-turn context awareness |
| pi_011 | Prompt Injection | Fill-in-the-blank instruction | Implicit rather than explicit injection |
| et_002 | Encoding Trick | ROT13 encoded injection | Letter frequency analysis partially effective; needs tuning |
| et_005 | Encoding Trick | Every-other-word steganography | Structural pattern, hard to distinguish from normal text |
| et_007 | Encoding Trick | Caesar cipher (+1) | Frequency analysis borderline; needs larger sample |

These gaps inform the v1.2 detection engine milestone.

---

## Architecture

```
corvus-mirage/
├── aria/                    ← Voice & vishing detection
│   ├── core/
│   │   └── detection_engine.py
│   └── routes/
│       ├── voice.py         ← Twilio + Deepgram pipeline
│       ├── redteam.py       ← Direct transcript endpoint
│       ├── sessions.py
│       └── health.py
├── gateway/                 ← AI prompt protection
│   ├── core/
│   │   ├── detection_engine.py  ← v1.1 tuned
│   │   ├── policy_engine.py
│   │   └── sanitizer.py
│   └── routes/
│       ├── inspect.py
│       ├── admin.py
│       └── health.py
├── red-team/                ← Validation engine
│   ├── core/
│   │   ├── attack_library.py    ← 55 attacks
│   │   ├── attack_runner.py     ← async runner
│   │   └── scorer.py            ← coverage reporting
│   ├── reports/             ← JSON + text output
│   └── main.py              ← single command entry
├── dashboard/               ← Unified UI (Phase 5)
├── shared/                  ← Cross-component utilities
│   ├── config.py
│   ├── alerting.py
│   ├── threat_intel.py
│   ├── event_bus.py
│   └── models.py
└── docs/
    ├── technical/
    │   └── roadmap.md       ← this file
    └── journal/
        ├── 2026-02-21.md
        ├── 2026-02-22.md
        └── 2026-02-24.md
```

---

## Services

| Component | Port | Protocol |
|-----------|------|----------|
| ARIA | 8001 | HTTP + WebSocket |
| Gateway | 8002 | HTTP + WebSocket |
| Dashboard | 5175 | HTTP |

---

## Pitch Target

**Primary:** Anthropic — platform built on Claude SDK, protects AI deployments, demonstrates responsible AI security tooling

**Secondary:** Enterprise security vendors (CrowdStrike, Palo Alto, etc.), SOC tool integrators, any organization deploying AI at scale

**Differentiator:** Shannon (XBOW benchmark leader) protects web apps from attackers. Corvus Mirage protects AI systems from adversarial inputs AND protects humans from AI-era social engineering. Different attack surface, different solution, validated by benchmark.

---

*"The raven sees everything. The mirage is what the attacker sees."*
