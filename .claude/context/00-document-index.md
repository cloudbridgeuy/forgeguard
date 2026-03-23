# ForgeGate — Document Index

> Complete documentation set for ForgeGate: authorization infrastructure for modern applications.

---

## Documents

| # | Title | Type | Description |
|---|-------|------|-------------|
| 01 | [Discussion Summary](01-discussion-summary.md) | Overview | End-to-end narrative of how ForgeGate was designed, from IAM question to full product shape |
| 02 | [SaaS Integration Guide](02-technical-saas-integration.md) | Technical | Developer guide for using ForgeGate as a fully managed service |
| 03 | [Self-Hosted Data Plane Guide](03-technical-self-hosted-data-plane.md) | Technical | Developer guide for deploying the data plane in your own AWS account |
| 04 | [Multi-Region & DR Architecture](04-multi-region-dr-architecture.md) | Technical | Multi-region deployment with honest constraints and RTO/RPO analysis |
| 05 | [Features & Competitive Differentiation](05-marketing-features-differentiation.docx) | Marketing | Product overview, feature list, and comparison table vs Auth0/Clerk/WorkOS |
| 06 | [Financial Analysis & Pricing](06-financial-analysis.docx) | Financial | AWS cost breakdown, pricing strategy, margin analysis, competitor comparison |
| 06b | [Cost Estimation Spreadsheet](06b-cost-estimation-spreadsheet.xlsx) | Financial | Interactive spreadsheet with editable assumptions |
| 07 | [AI Security Narrative](07-marketing-ai-security.docx) | Marketing | Why ForgeGate makes AI-generated applications secure by construction |
| 08 | [Control Plane UI Design](08-technical-control-plane-ui.md) | Technical | Dashboard architecture: Model Studio, Operations, God Mode, webhooks, dogfooding |
| 09 | [Authorization Testing](09-technical-authorization-testing.md) | Technical | Auto-generated test suite, CI/CD integration, custom test cases |
| 10 | [Authorization Testing (Marketing)](10-marketing-authorization-testing.docx) | Marketing | Why automated authorization testing is a competitive advantage |
| 11 | [Identity Engine (Rust)](11-technical-identity-engine-rust.md) | Technical | Typestate state machines, event log, metrics, timeouts, Flow Reaper, God Mode operations |
| 12 | [Internal Back Office](12-technical-back-office.md) | Technical | Customer management, analytics, support tickets, impersonation, alerting |
| 13 | [SDK Architecture & Conformance](13-technical-sdk-architecture-conformance.md) | Technical | Rust core + FFI wrappers, JSON conformance fixtures, native transition path |
| 14 | [Tutorial: TODO App](14-tutorial-todo-app.md) | Tutorial | End-to-end walkthrough building a secured multi-tenant TODO API in 27 minutes |

---

## Reading Order

**For understanding the product vision:** 01 → 14 → 05 → 07

**For technical architecture:** 08 → 11 → 13 → 04

**For developer integration:** 02 (or 03) → 09 → 14

**For business context:** 06 → 12 → 10
