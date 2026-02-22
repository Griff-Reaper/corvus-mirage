# Corvus Mirage

> *The raven watches everything. The mirage is what the attacker sees.*

**Corvus Mirage** is an AI security platform that protects both AI systems and the humans who operate them — covering the two most underprotected attack surfaces in modern enterprise: AI model exploitation and social engineering.

---

## The Problem

AI is being deployed everywhere. Help desks use it. Customer service uses it. Internal tools use it. And as AI becomes the interface between humans and organizations, it becomes the target.

Existing security tools weren't built for this:
- **Traditional WAFs** don't understand prompt injection or adversarial AI inputs
- **Annual pentests** leave 364 days of exposure in fast-moving AI deployments
- **No real-time detection exists** for vishing attacks targeting employees while they're on the phone

The MGM Resorts breach started with a 10-minute phone call. A social engineer impersonated an employee and walked through the front door. **$100 million in damages.** Corvus Mirage is built so that call never succeeds.

---

## The Platform

Corvus Mirage is three components that work independently or as a unified platform:

### ARIA — Deception & Detection Engine
A dual-mode system that operates as both an AI honeypot and a real-time vishing detection layer.

- **Web Honeypot:** Lures attackers, fingerprints techniques, profiles behavior with MITRE ATT&CK tagging and honeytoken deployment
- **Vishing Detection:** Answers inbound calls, transcribes in real time, detects social engineering mid-conversation, and surfaces live threat profiles to your security team before the call ends
- **Cross-vector correlation:** Identifies the same attacker across web and voice sessions

### Gateway — AI Protection Layer
A model-agnostic security layer that sits in front of any AI deployment.

- Detects prompt injection, jailbreak attempts, adversarial inputs, and model extraction probing
- Works with Claude, GPT, Gemini, or any open-source model
- Configurable rulesets, admin panel, rate limiting
- Feeds all incidents to the Corvus Mirage dashboard

### Red Team Simulator — Validation Engine
Continuously attacks ARIA and Gateway to prove they work.

- Multi-turn attack chains with escalation — not single prompts
- Voice attack simulation for vishing scenario validation
- Scheduled autonomous runs
- Pentester-grade reports with reproducible proof-of-concept findings
- Benchmark scoring system for citable improvement tracking

---

## Why Corvus Mirage

| | Traditional Tools | Shannon | Corvus Mirage |
|--|--|--|--|
| Web app vulnerability scanning | ✓ | ✓ | — |
| AI system protection | — | — | ✓ |
| Real-time vishing detection | — | — | ✓ |
| Continuous AI red teaming | — | ✓ | ✓ |
| Unified offensive + defensive loop | — | — | ✓ |

---

## Built With

- Python
- Claude SDK + Anthropic API
- Twilio Voice
- Deepgram (real-time STT)
- LangChain
- FastAPI
- React (dashboard)

---

## Status

🚧 **Active Development** — Started February 2026

Documentation and build journal available in `/docs`.

---

## About

Built by a Navy veteran and AI security engineer with hands-on experience in enterprise security operations, CrowdStrike Falcon administration, and AI system development. Corvus Mirage is designed to be the security layer that AI deployments don't know they need yet — but will.

---

*For inquiries, collaboration, or licensing discussions — reach out directly.*
