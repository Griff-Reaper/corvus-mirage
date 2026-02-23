# Corvus Mirage — Technical Roadmap

---

## Platform Overview

Corvus Mirage is a three-component AI security platform designed to detect, deceive, and validate threats across voice and prompt attack vectors.

```
ARIA              ← Dual-mode honeypot + real-time vishing detection
Gateway           ← Model-agnostic AI prompt protection layer
Red Team Simulator ← Adversarial validation engine
Dashboard         ← Unified SOC command center
Shared            ← Threat intelligence DB + event bus
```

**Target:** Enterprise security companies (CrowdStrike, Anthropic)
**Positioning:** End-to-end AI attack surface coverage — the only platform that detects coordinated attackers operating across both voice and prompt vectors simultaneously.

---

## 7-Day Build Plan

### ✅ Day 1 — ARIA Core
Single-session voice pipeline. Twilio webhook → Deepgram real-time STT → Claude detection engine → threat assessment. Live phone call validated end to end.

**Delivered:**
- FastAPI infrastructure with Twilio webhook handling
- Deepgram real-time speech-to-text integration
- Claude-powered social engineering detection
- WebSocket manager for real-time dashboard streaming
- Session management and threat scoring
- ARIA SOC frontend (React/Vite) on port 5174
- Domain secured: corvusmirage.ai (Cloudflare)

---

### ✅ Day 2 — Gateway + Shared Intelligence + Unified Dashboard

#### Part 1: Gateway
Merged Prompt-Shield and Prompt-Firewall into a single clean AI protection layer. Three-layer ensemble detection engine with configurable policy management.

**Delivered:**
- Three-layer detection: rule-based (40%) + statistical (25%) + semantic (35%)
- Hard override on strong rule matches — single injection pattern forces minimum 80% of rule score
- Sanitizer with PII redaction and malicious pattern removal
- Runtime policy management via admin API
- WebSocket manager mirroring ARIA's for unified dashboard compatibility
- Detection tuning: first hit scores 70, threshold lowered to 40
- Processing time: ~5ms per inspection

#### Part 2: Shared Threat Intelligence Layer
Wired ARIA and Gateway into a single SQLite database with cross-vector correlation.

**Delivered:**
- Unified `ThreatEvent` schema accommodating both voice and prompt threat types
- `threat_events` table — every individual detection from both components
- `attacker_profiles` table — cross-vector actor records
- `get_cross_vector_sessions()` — finds actors appearing in both ARIA and Gateway events
- Shared async event bus for real-time cross-component awareness
- Both components writing to shared DB on every malicious detection

#### Part 3: Unified SOC Dashboard
Single operator interface showing ARIA voice threats and Gateway prompt injections in real time.

**Delivered:**
- Unified dashboard on port 5175 (extended from ARIA's production-quality frontend)
- Dual WebSocket connections — ARIA (8001) and Dashboard FastAPI (8080)
- DB polling architecture for cross-process Gateway event delivery (2s latency)
- ALL / ARIA / GATEWAY feed filters
- Six-counter unified stats bar
- Cross-vector actor flagging in session list
- Gateway prompt attempts visible in session detail panel
- Both ARIA and GATEWAY connection indicators live simultaneously

**Port map:**
```
8001  ARIA backend
8002  Gateway backend
8080  Dashboard FastAPI
5174  ARIA frontend (component-level)
5175  Corvus Mirage unified dashboard
```

---

### 🔲 Day 3 — Red Team Simulator (Core)
The third Corvus Mirage component. Generates adversarial attacks against both ARIA and Gateway — prompt injections, jailbreaks, vishing scripts. Validates detection coverage and produces a scored report.

**Goal:** Be able to say "we tested it and it catches X% of known attacks."

**Planned:**
- Attack library: prompt injection variants, jailbreak attempts, vishing scripts
- Attack runner targeting both ARIA and Gateway endpoints
- Detection coverage scoring per attack category
- Known evasion testing (single-word bypass, encoding tricks, role manipulation)
- Scored validation report

---

### 🔲 Day 4 — Red Team Simulator (Integration) + Platform Hardening
Wire simulator output into the shared DB so attack runs appear in the dashboard. Fix known gaps identified during Day 3 runs.

**Planned:**
- Simulator attack runs visible in unified dashboard feed
- IP correlation in Gateway (currently missing)
- Alert webhook URL configured
- Detection gap fix: single-word evasion bypasses rule-based layer
- ARIA voice events piped into unified feed (currently connected but not rendering)
- Tighten any loose ends across all three components

---

### 🔲 Day 5 — Pitch Documentation + Demo Prep
Everything needed to actually show this to CrowdStrike or Anthropic.

**Planned:**
- README overhaul — platform summary, architecture, quickstart
- Architecture diagram (voice + prompt attack surface, component interaction)
- One-page platform summary for non-technical stakeholders
- Recorded demo flow
- LinkedIn posts for each major component milestone

---

## Known Issues / Technical Debt

| Issue | Component | Priority | Notes |
|-------|-----------|----------|-------|
| Single-word evasion | Gateway | High | "Ignore previous instructions" without "all" scores 27.3, below threshold |
| ARIA events not in unified feed | Dashboard | High | WS connected, frontend not piping ARIA message events into shared feed |
| Alert webhook not configured | ARIA | Low | Blank URL in .env, non-critical |
| No IP correlation | Gateway | Medium | Would enable cross-vector correlation by IP, not just session ID |
| In-memory event bus | Shared | Low | Cross-process publishing doesn't work — DB polling is the current workaround |

---

## Architecture

```
                    ┌─────────────────────────────────┐
                    │     Corvus Mirage Dashboard      │
                    │         localhost:5175            │
                    │   React/Vite — SOC Command Center │
                    └──────────┬──────────┬────────────┘
                               │          │
                    ┌──────────▼──┐  ┌────▼──────────┐
                    │    ARIA     │  │  Dashboard API  │
                    │  :8001      │  │     :8080       │
                    │  Voice +    │  │  Shared event   │
                    │  Honeypot   │  │  bus + stats    │
                    └──────┬──────┘  └────────┬────────┘
                           │                  │
                    ┌──────▼──────┐           │
                    │   Gateway   │           │
                    │   :8002     │           │
                    │  Prompt     │           │
                    │  Inspection │           │
                    └──────┬──────┘           │
                           │                  │
                    ┌──────▼──────────────────▼────────┐
                    │         Shared Layer              │
                    │  threat_intel.db (SQLite)         │
                    │  threat_events + attacker_profiles│
                    │  event_bus (in-memory, per-process)│
                    └───────────────────────────────────┘
```

---

*Last updated: February 22, 2026 — Day 2 complete.*
