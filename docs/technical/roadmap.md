# Corvus Mirage — Foundation Roadmap

> *"The raven watches everything. The mirage is what the attacker sees."*

**Version:** 0.1 — Foundation  
**Started:** February 21, 2026  
**Status:** In Development

---

## Vision

Corvus Mirage is an AI security platform that protects both AI systems and the humans who operate them. While existing tools like Shannon target web application vulnerabilities, Corvus Mirage addresses two underprotected attack surfaces: AI systems themselves (prompt injection, adversarial inputs, model exploitation) and the human layer (social engineering, vishing, pretexting).

The result is a complete offensive-defensive loop — three components that validate, protect, and detect across every major AI-era threat vector.

---

## Platform Architecture

```
┌─────────────────────────────────────────────────────┐
│                  CORVUS MIRAGE                       │
│                                                      │
│  ┌──────────┐   ┌──────────┐   ┌──────────────────┐ │
│  │  ARIA    │   │ GATEWAY  │   │  RED TEAM SIM    │ │
│  │ Honeypot │   │   AI     │   │   Validation     │ │
│  │ + Vishing│   │Protection│   │     Engine       │ │
│  └────┬─────┘   └────┬─────┘   └────────┬─────────┘ │
│       │              │                  │            │
│  ─────┴──────────────┴──────────────────┴──────────  │
│              Shared Threat Intelligence              │
│              Unified Dashboard & Alerting            │
└─────────────────────────────────────────────────────┘
```

All three components operate independently but feed into a shared threat intelligence layer and unified dashboard. Patterns learned in one component inform the others.

---

## Component 1: ARIA

**Role:** Deception and detection engine — two operating modes.

**Mode 1 — Web Honeypot:**
Presents as a legitimate AI-powered interface. Lures attackers, fingerprints their techniques, maps attack patterns, deploys honeytokens, and logs everything with full attacker profiling and MITRE ATT&CK tagging.

**Mode 2 — Vishing Detection & Response:**
Answers inbound calls via Twilio. Real-time speech-to-text via Deepgram feeds ARIA's detection engine. Social engineering techniques are identified mid-call. Live transcript and threat profile surface to the dashboard instantly. IT team is alerted in real time and can intervene while the call is active.

**Foundation Build Items:**
- [ ] Fork existing ARIA codebase into monorepo, apply Corvus Mirage branding
- [ ] Twilio Voice integration — inbound call handling
- [ ] Deepgram real-time STT — streaming transcript into detection engine
- [ ] Voice session handling alongside existing text sessions in dashboard
- [ ] Real-time transcript panel in dashboard UI
- [ ] Geolocation and caller metadata storage (from Twilio)
- [ ] Call tracing and origin intelligence visualization
- [ ] Attacker profiling extended to voice-specific techniques:
  - Pretexting
  - Urgency and authority impersonation
  - Credential harvesting via voice
  - Verification bypass attempts
- [ ] Cross-session correlation — same attacker across voice and web vectors
- [ ] Alert pipeline — Slack, email, webhook

**Definition of Done:** A phone number answers via ARIA, detects social engineering in real time, surfaces live transcript + attacker profile to dashboard, fires alerts to IT team.

---

## Component 2: Gateway

**Role:** Model-agnostic AI protection layer. Sits in front of any AI deployment and inspects all traffic in and out.

**What it detects:**
- Prompt injection attacks
- Jailbreak attempts
- Adversarial inputs
- Data exfiltration through model context
- Model extraction probing
- Anomalous usage patterns

**Foundation Build Items:**
- [ ] Merge Prompt-Shield and Prompt-Firewall into single clean codebase
- [ ] Proper REST API with full documentation
- [ ] Model-agnostic design — works with Claude, GPT, Gemini, open source
- [ ] Configurable ruleset — organizations define thresholds and policies
- [ ] Admin panel for rule management
- [ ] Rate limiting and anomaly detection on usage patterns
- [ ] Detection logging pipeline feeding into Corvus Mirage dashboard
- [ ] Alerting integration

**Definition of Done:** Any AI deployment routes through Gateway via API, receives real-time protection, and surfaces incidents to unified dashboard.

---

## Component 3: Red Team Simulator

**Role:** Continuously attacks ARIA and Gateway to validate they work, then reports findings with reproducible proof.

**Foundation Build Items:**
- [ ] Multi-turn attack chains with escalation — not single prompts
- [ ] Attack categories mapped to ARIA and Gateway defense coverage
- [ ] Voice attack simulation feeding into ARIA's vishing detection
- [ ] Scheduled autonomous attack runs
- [ ] Pentester-grade findings report with:
  - Reproduction steps
  - Severity scoring
  - Detected vs. missed breakdown
- [ ] Benchmark scoring system — track improvement over time (citable like XBOW)

**Definition of Done:** One command launches a full attack campaign against ARIA and Gateway, produces a structured findings report, feeds detection gaps back into the system.

---

## Unified Layer

**Shared across all components:**
- Single dashboard — all incidents, blocks, and findings in one place
- Shared threat intelligence database
- Unified alerting — Slack, email, webhook, configurable
- Single installation — deploy all three or individually
- Consistent logging format across components

---

## Build Order

| Phase | Focus | Components |
|-------|-------|------------|
| 1 | Platform setup | Monorepo, branding, shared config, dashboard shell |
| 2 | ARIA voice layer | Twilio, Deepgram, transcript panel, geolocation |
| 3 | Gateway consolidation | Merge Prompt-Shield + Prompt-Firewall, REST API |
| 4 | Red Team enhancement | Voice attacks, scheduled runs, benchmark scoring |
| 5 | Unified intelligence | Wire components together, shared threat DB |
| 6 | Docs + Demo environment | Pitch-ready, installable, documented |

---

## Infrastructure Status

| Item | Status | Notes |
|------|--------|-------|
| `corvusmirage.ai` domain | ✅ Secured | Cloudflare Registrar, expires Feb 21 2028 |
| Cloudflare security | ✅ Active | Bot Fight Mode on, DNSSEC enabled |
| Twilio account | ✅ Created | Trial, phone number assigned |
| Deepgram account | ✅ Created | GitHub SSO |
| Anthropic API | ✅ Ready | Existing key |
| SSL/TLS configuration | ⏳ Deferred | Configure at deployment time |
| VPS/hosting | ⏳ Deferred | DigitalOcean or AWS, configure at deployment |

---

## Success Criteria (Pitch Ready)

- [ ] All three components deploy from a single repo with clear setup instructions
- [ ] ARIA answers a live phone call and detects a social engineering attempt in real time
- [ ] Gateway blocks prompt injection across at least two different AI models
- [ ] Red Team Simulator produces a benchmark score that can be cited
- [ ] Dashboard tells a complete story — no gaps, no rough edges
- [ ] Documentation is thorough enough for a technical reviewer to understand and evaluate without a demo

---

*Roadmap is a living document. Updated as the build evolves.*