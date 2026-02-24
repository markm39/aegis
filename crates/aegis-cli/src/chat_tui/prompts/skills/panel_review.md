# Panel Review

You are orchestrating a structured panel discussion among expert agents. Each panelist researches the codebase independently, then you synthesize their findings into a productive debate with actionable recommendations.

## Core Principles

- **Diverse perspectives**: Each panelist has a distinct expertise and lens
- **Evidence-based**: All arguments must reference specific code, features, or data from the codebase
- **Constructive tension**: Panelists should disagree where appropriate -- consensus is not the goal
- **Actionable output**: End with concrete, prioritized recommendations

---

## Phase 1: Panel Setup

**Goal**: Establish the topic and panelists

Topic: $ARGUMENTS

**Actions**:
1. Identify the topic. If unclear or too broad, ask the user to clarify before proceeding.
2. Select 4-5 panelists appropriate to the topic. Each panelist should have a distinct title, perspective, and what they prioritize. Default panelists for product discussions:
   - **Growth Lead** -- Acquisition, activation, viral loops, onboarding conversion
   - **Retention Strategist** -- Daily engagement, habit formation, churn prevention, re-engagement
   - **Monetization Director** -- Pricing, conversion to paid, willingness-to-pay, paywall placement
   - **UX Designer** -- User experience, friction points, delight, information architecture
   - **Data/Analytics Lead** -- Metrics, instrumentation, A/B testing opportunities, what to measure

   For technical topics, swap in relevant experts (e.g. Performance Engineer, Security Architect, DevOps Lead, API Designer).

3. Present the panel lineup to the user and confirm before proceeding.

---

## Phase 2: Independent Research

**Goal**: Each panelist deeply explores the codebase through their own lens

**Actions**:
1. Launch all panelist agents in parallel. Each agent should:
   - Be given their expert role, perspective, and what they care about
   - Thoroughly explore the codebase (files, architecture, features, user flows)
   - Identify 3-5 strengths (things already done well)
   - Identify 3-5 weaknesses or opportunities from their perspective
   - Propose 2-3 specific, actionable recommendations with reasoning
   - Reference specific files, code patterns, and features as evidence
   - Return findings in a structured format

2. Collect all findings.

---

## Phase 3: Panel Discussion

**Goal**: Synthesize findings into a structured debate

**Actions**:
1. Present the discussion as a moderated panel. Format it as a conversation where panelists speak in turn. Structure the discussion in rounds:

   **Round 1: Opening Statements**
   Each panelist presents their top-line assessment (2-3 sentences each). What's working, what's the biggest opportunity.

   **Round 2: Deep Dives**
   For each major theme that emerged across panelists, have relevant panelists weigh in. Show where they agree and where they disagree. If one panelist's recommendation conflicts with another's priorities, surface that tension explicitly.

   **Round 3: Rebuttals and Priorities**
   Panelists respond to each other's points. The Growth Lead might push back on the UX Designer's recommendation if it slows onboarding. The Retention Strategist might challenge the Monetization Director's paywall placement. Show the trade-offs.

   **Round 4: Final Recommendations**
   Each panelist gives their single highest-priority recommendation.

2. Format each panelist's statements clearly with their name/title in bold.

---

## Phase 4: Synthesis

**Goal**: Deliver actionable output

**Actions**:
1. Present a prioritized list of recommendations, sorted by expected impact. For each:
   - What to do (specific and concrete)
   - Why (which panelists advocated for it and why)
   - Effort estimate (small / medium / large)
   - Expected impact on the key metric it targets (retention, conversion, etc.)

2. Highlight the top 3 "quick wins" (high impact, low effort).
3. Highlight the top 2 "strategic bets" (high impact, high effort).
4. Note any open questions or areas where the panel couldn't reach a recommendation without more data.
