# Aegis Orchestrator Computer-Use Runtime Contract

Status: draft for implementation
Scope: Phase 0 baseline for fast sense-act orchestration and compliance integration

## Goals

- Enable orchestrator agents to run continuous computer-use loops with low latency.
- Keep all privileged runtime actions policy-gated and audit-visible.
- Fail closed when policy/control state is unavailable.

## Fast Sense-Act Envelope

The runtime must satisfy this default envelope:

- Sense (capture): target 30 FPS with less than 100ms median capture latency.
- Act (input): less than 50ms median input injection latency.
- Think (planner/executor): execute 3-10 micro-actions per model response when risk permits.
- Control: do not require per-action human confirmation unless policy indicates medium/high risk gating.

The envelope is represented in code by `aegis_toolkit::contract::FastLoopEnvelope`.

## Tool Action Taxonomy

The runtime action model is represented by `aegis_toolkit::contract::ToolAction`.

Primary action families:

- Capture: `ScreenCapture`, `TuiSnapshot`, `BrowserSnapshot`
- Input: `MouseMove`, `MouseClick`, `MouseDrag`, `KeyPress`, `TypeText`, `TuiInput`
- Focus/navigation: `WindowFocus`, `BrowserNavigate`

Each action exposes:

- `policy_action_name()` for stable Cedar/audit identifiers
- `risk_tag()` for approval workflow and risk-aware execution

## Risk Tags and Default Handling

Risk tags are represented by `aegis_toolkit::contract::RiskTag`.

- `low`: read-only or low-impact observation/movement actions
- `medium`: actions that can mutate UI/app state through input
- `high`: context switching/navigation actions with broader blast radius

Default policy stance:

- `low`: allow when policy path is healthy and principal is authorized
- `medium`: allow with policy mediation; may require explicit orchestrator guardrails
- `high`: allow only with explicit policy permit and clear provenance metadata

## Policy and Compliance Hooks

Every computer-use action must be mapped to a Cedar-evaluable action and recorded in the ledger with provenance metadata.

Minimum provenance for each executed action:

- action name
- risk tag
- capture latency (if applicable)
- input latency (if applicable)
- frame id and/or window id (if applicable)
- runtime session id

These fields are represented by `aegis_toolkit::contract::ToolResult`.

## Fail-Closed Requirements

If policy evaluation, control-plane routing, or runtime mediation is unavailable:

- deny action execution by default
- return explicit denial reason
- emit audit event marking fail-closed decision path

No silent fallback to unmediated execution is allowed in production mode.

## Orchestrator vs Worker Boundaries

- Orchestrator agents may use computer-use runtime actions.
- Worker agents remain tool-limited and instruction-driven.
- Orchestrator should route high-risk or ambiguous operations to explicit approval paths.

## Implementation Sequence

1. Land contract types and unit tests in `aegis-toolkit`.
2. Add daemon protocol commands for execute/start/stop computer-use sessions.
3. Wire Cedar mapping and ledger provenance for all action variants.
4. Implement macOS runtime adapters (capture/input/window) behind same contract.
5. Add CDP-first browser runtime integration under same action taxonomy.
