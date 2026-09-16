# AGENTS.md — cyber-soc

Product-specific notes for AI agents working in this repo. Read
`~/projects/cyber-specs/AGENTS.md` first for the org-wide rules (mise/uv/Bun,
Postgres naming, Docker Debian bases, Caddy, no `|| true`, specs/ sync on
public-surface changes).

## What this product is

Cyber SOC Copilot — an N1/N2 SOC/CSIRT AI specialist: ingests Wazuh/Elastic
events, tags them with MITRE ATT&CK, scores traffic risk (IP/port/protocol +
threat intel), and answers analyst questions via a local LLM. Full spec: see
`README.md` → "Escopo original" and `PLANO.md`.

## Auth is intentionally NOT the HUB SSO model

Unlike `cyber-sdo`, this product has its own local email/password login
(`app/auth/`) with an admin-bootstrapped account and no self-registration —
that's an explicit product requirement, not an oversight. If this product is
later registered with the mfe-platform HUB, auth would need a real design
decision (keep local auth behind the HUB shell, or migrate to HUB SSO
entirely) — don't silently swap one for the other.

## Standalone, not merged with `socless` or `cyber-sdo`

Two other Cyber SOC/security-orchestrator-shaped platforms already exist in
`~/projects` (`socless`, `cyber-sdo`). This one is deliberately separate — do
not copy code between them or suggest merging without being asked.
