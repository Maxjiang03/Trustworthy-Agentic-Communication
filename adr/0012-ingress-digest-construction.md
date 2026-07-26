# 0012 — `ingress_request_digest` adopts `H_JCS`, computed recorder-side at the tool

## Context

ADR 0009 classified `ToolIngressEvent.ingress_request_digest` as **(c) deferred to G-7**: the
architecture document named no construction for it and no Part I predicate compares it, but the
constraint was recorded that if any oracle check compares it against an `H_JCS`-governed digest
it MUST be `H_JCS`-governed. Gate G-7 built the `ToolIngressEvent` recorder
(`src/harness/effect_ledger.py`), so the deferral is due. This ADR settles it; it extends the
ADR 0009 classification and re-opens neither ADR 0009 nor ADR 0003.

## Decision

[DESIGN] **`ingress_request_digest` is governed by `H_JCS`** (ADR 0009: lowercase-hex SHA-256
over `b"AASC-JCS-DIGEST" ‖ 0x01 ‖ u32be(len(C)) ‖ C`, C = the RFC 8785 canonical bytes). The
reason is the one ADR 0009 anticipated: the field exists to be compared against
`intended_request_digest` and `effect_request_digest` — both `H_JCS`-governed — so any other
construction would make the comparison structurally unequal on honest inputs (the same
false-rejection class ADR 0011 closes for the commitment family).

**What it is computed over.** The **arguments mapping the tool is invoked with** — the
tool-call arguments object as it reaches the tool function, excluding the SDK-injected context
parameter (`Tool.context_kwarg`), which is transport machinery, not an argument. This **is the
same object domain as `intended_request_digest`**: intended is `H_JCS` over the *sealed
intended* arguments object; ingress is `H_JCS` over the arguments object *actually presented
at the tool*. On an untampered path the two are equal; divergence is exactly the F3
body-mutation signal. [VERIFIED, gate G-7: on the benign path
`ingress_request_digest == effect_request_digest == H_JCS(arguments)`, byte-identical.]

**Who computes it.** The **recorder**, installed harness-side at the tool (D21): the SUT never
supplies the digest, and the recorder writes through the harness-held ledger channel the SUT
cannot reach (G-7.B). The SUT-side computation, when the arms are built, must remain an
independent implementation, and the oracle never consumes a SUT-computed digest (§F.1).

**Normalization caveat (recorded, not resolved here).** The SDK validates/coerces arguments
before invoking the tool (`FuncMetadata.call_fn_with_arg_validation`: JSON pre-parse +
pydantic model validation), so the ingress object is the *post-validation* mapping. Pilot and
confirmatory fixtures keep arguments in-model, where this normalization is the identity; a
divergence introduced by coercion would surface as a digest mismatch — fail-visible, not
fail-silent. Re-examined when the arms are built (G-11/G-12).

## Status

accepted — 2026-07-26

## Consequences

- The ADR 0009 classification is now: `canonical_request_digest`, `intended_request_digest`,
  `effect_request_digest`, **`ingress_request_digest`** → (a) `H_JCS`; the
  `DeclassificationArtifact.request_digest` and `payload_digest` deferrals stand (F4 label
  plumbing / G-15).
- `schema.py`'s `ingress_request_digest` comment points here (same pass).
- The oracle may compare ingress against intended/effect/oracle digests with plain string
  equality; all four share one construction and one rendering (lowercase hex).
