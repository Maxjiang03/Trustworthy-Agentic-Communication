# 0030 — Label plumbing: the six constructions, and one boundary-owned reference monitor

## Context

ADR 0009 fixed `H_JCS` and then listed what it deliberately did **not** fix, as *category (c)*:
`payload_digest`, `authz_context_hash`, and `label_assertions_digest`, deferred to *"the F4 label
decision and G-15"*. That deferral has held since the beginning of the repository, and it is the
reason three of the five §E.3 threat families cannot be scored at all:

- **F3** (`context_binding`) needs a request binding an artifact can be signed over.
- **F4** (`label_confusion`) needs a payload label a boundary can *verify* rather than read.
- **F5** (`approval_forgery`) needs an approval bound to *one* request.

Nine arms exist and ten gates pass; the study can score F1 and three F2 subfamilies and nothing
else. Both conjuncts that would score the rest — `context_policy_ok` and `approval_artifact_ok` —
currently **refuse anything presented**, naming this ADR as the reason. That refusal is honest and
fail-closed, but it is not a measurement: an arm that refuses every labelled request scores
identically to an arm that verifies labels correctly, so F4 and F5 have no discriminating power.

Two further constraints shape the decision, and they pull against each other:

1. **§E.4's `A†` cells.** The predicted matrix marks the OAuth arms `A†` on F3/F4/F5, glossed
   *"admitted **absent** the shared monitor"*. So the monitor must be attachable to an OAuth arm —
   otherwise the dagger is unfalsifiable and the study reports a monitor-configuration difference as
   a capability-versus-OAuth advantage. That is exactly what gate **G-15** forbids.
2. **§A.5's conjunct list.** `context_policy_ok` and `approval_artifact_ok` are boundary conjuncts
   in the *same* list as `crypto_chain_ok` and `htc_chain_ok`, which are capability-specific. If the
   label machinery were built *inside* the capability path, no OAuth arm could ever run it, and (1)
   would be impossible to satisfy.

## Decision

`[DESIGN]` **Six new constructions in the ADR 0003/0009/0016/0018 tagged-versioned-length-delimited
family, and one reference monitor owned by the boundary rather than by any arm.**

    digest        = lowercase_hex( SHA-256( TAG || VERSION || u32be(len(C)) || C ) )
    signing input =                         TAG || VERSION || u32be(len(C)) || C

`VERSION = 0x01`; any other value fails closed. No algorithm byte — a hash change is a new VERSION,
not a parameter. `C` is the canonical bytes of that tag's own domain.

| Construction | Tag | `C` is |
|---|---|---|
| `payload_digest` | `AASC-PAYLOAD-DIGEST` | the data **value**: `str` UTF-8 encoded, `bytes` as-is |
| `authz_context_hash` | `AASC-AUTHZ-CTX` | RFC 8785 bytes of the six-member §F.2 object |
| `label_assertions_digest` | `AASC-LABELSET-DIGEST` | RFC 8785 bytes of the **sorted** list of join keys |
| `LabelAssertion` signature | `AASC-LABEL-v1` | RFC 8785 bytes of the assertion payload |
| `DeclassificationArtifact` signature | `AASC-DECLASS-v1` | RFC 8785 bytes of the artifact payload |
| `ApprovalArtifact` signature | `AASC-APPROVAL-v1` | RFC 8785 bytes of the envelope's `payload` |

**Six tags, not fewer.** G-11 tested domain-tag confusion in both directions and found it real, and
ADR 0018 records that `ath` and `access_token_hash` take the *same input bytes* and are kept apart by
the tag alone. Merging any two domains here would let a signature over one artifact type be replayed
as a signature over another — a declassification presented as an approval, most obviously. All six
join `at_digest._TAGS_IN_USE` in the same commit, under the existing pairwise-distinctness assertion
that covers the whole family.

### `payload_digest` is over a VALUE, not a JSON object

ADR 0009 said this explicitly: *"the payload domain is a data value (not necessarily a JSON object),
so `H_JCS` MUST NOT be assumed"*. §A.6 resolves label assertions **by payload digest**, and that
resolution is a **join**: the same value must yield the same digest whether it arrives as a JSON
string field inside a tool argument, as `payload_digest` on an `EffectEvent`, or on a
`ToolIngressEvent`. Under `H_JCS` the digest would depend on the surrounding object and no such key
would exist. A value that is neither `str` nor `bytes` **fails closed** rather than being serialized
by a rule this ADR did not fix — an unstable join key is not a key.

### `authz_context_hash` is mechanism-neutral, and that is the whole design

§F.2 defines it over `task_id`, `audience`, `tool`, `canonical_request_digest`, `resource_owner`,
`oauth_actor` — and **not one of those names a capability, an HTC, an INV, or a DPoP key.** That is
what makes a single shared monitor possible: an OAuth arm holding no capability token computes
*exactly the same value* for the same request as `B3` does. Had this hash been defined over the INV,
constraint (1) above would be unsatisfiable and `A†` unfalsifiable.

The function is **keyword-only and exhaustive**: all six inputs must be supplied, so a caller cannot
quietly bind fewer of them and produce a value that looks like this one. `canonical_request_digest`
is `H_JCS` of the arguments **as the boundary re-serializes them**, never a value read from the
presented INV — the boundary must not accept the requester's own account of what it requested.

### Worked example — both implementations reproduce these bytes

    value  = "quarterly revenue: 4.2M"
    payload_digest = 58c2164bbc62f7ce24846b98a9c3d290a139a26e18379223ef901db70952b555

    arguments = {"to": "partner@example.test", "subject": "Q3", "body": <value>}
    canonical_request_digest = H_JCS(arguments)
                             = 2347288282d7524da93c726840ed973a767c884b51939603a72a1746ec458b39

    C (RFC 8785, alphabetical by member name):
    {"audience":"https://mcp.aasc.local/tools",
     "canonical_request_digest":"2347288282d7524da93c726840ed973a767c884b51939603a72a1746ec458b39",
     "oauth_actor":["https://as.aasc.local","agent-specialist"],
     "resource_owner":["https://as.aasc.local","user-alice"],
     "task_id":"task-7","tool":"mail.send"}

    authz_context_hash      = 96d6ede29b459cae481674cb88aeb4a61bd3c530d7a0369771bcb74c2107a5ab
    label_assertions_digest([])                 = 59d8ec21cab8de767fdf16c246c6a168fd9fd1049fdaa3bd0637f9cd3836232b
    label_assertions_digest([payload_digest])   = eee883389e93be9edcccd8dd5859e200ec11a3feb79f70462341af4c2f234bed

The empty label set has a **real digest, not a sentinel**, so an unlabelled invocation is bound as
*"no labels"* rather than as *"this field was not filled in"* — swapping a label set into an
already-signed INV is therefore detectable even when the original carried none. Sorting the join
keys makes the binding independent of presentation order, so a reordering that changes nothing does
not change the digest.

### The reference monitor is owned by the boundary, and `monitor_attached` is CONFIGURATION

`ContextApprovalMonitor` lives in `src/sut/authz/reference_monitor.py`, takes no capability, no HTC
and no INV, and is constructed from four things: the frozen rows 4/6 policy, the trusted **label
issuer** keys, the trusted **approver** keys, and the policy version. An arm calls it; an arm does
not contain it. `B3` and `B3⁺` run it because their §E.5 bitmasks set `context = 1` and
`approval = 1` — their **ladder position** — and the identical object is attachable to an OAuth arm
as a run configuration.

`monitor_attached ∈ {true, false}` is therefore **a property of a run, not of an arm**. Every F4/F5
cell must be reported alongside it, and G-15 fails the block if any is reported without it.

**Two trusted key sets, deliberately disjoint.** A label issuer asserts what data *is*; an approver
authorizes an *action*. One key doing both would let whoever labels a payload also approve a
high-risk action on it, so the monitor **refuses to construct** when a kid appears in both sets, and
the two derivations use different ADR 0007 `info` labels so they cannot collide by accident.

### Freshness: Δ applies to the two request-bound artifacts, not to labels

ADR 0027 froze one window, `Δ = 60 s`. Declassifications and approvals are bound to a single request
and are checked against it, and their `jti` values are consumed in the same Δ-scoped cache. **Label
assertions are not**: §A.6 states labels *"are asserted at ingestion by a trusted source (they exist
before task-time capability issuance)"*, so applying Δ would refuse every genuinely pre-labelled
payload. A `LabelAssertion` is bounded by its own `iat`/`exp` instead. Asymmetric on purpose, and
recorded here so the asymmetry is a decision rather than an oversight.

### Declassification is an acceptance path, not an exception

Rows 4/6 are evaluated over **verified** labels only. A declassification does not bypass the policy;
it changes one payload's effective label from `from_label` to `to_label` for one request, and only
if all of: the approver is trusted, the signature verifies in the `AASC-DECLASS-v1` domain, the
artifact's `request_digest` **equals this request's `authz_context_hash`**, the policy version
matches, `nbf ≤ now < exp`, the artifact is within Δ, the recipient/tool/task/audience match,
`from_label` equals a label that actually verified, the `(from, to)` pair is one the frozen policy
permits, and the `jti` is unused. The policy is then re-evaluated over the substituted label. So a
declassified egress can still be refused by rows 4/6 — which is the point.

### The ledger learns labels from ingestion, never from the request

`EffectEvent.data_labels_touched`, `EffectEvent.payload_digest`/`value_id` and
`ToolIngressEvent.payload_digest`/`value_id` have been in `src/harness/schema.py` since the
beginning with nothing populating them. They are populated by an instrument-side **ingestion label
directory** (`src/harness/policy/label_directory.py`), keyed by `payload_digest` and resolved by
**recomputing** that digest over the values the tool actually acted on.

**Not from the `LabelAssertion`s the request carried, and this is the load-bearing part.** §A.6 puts
labelling at ingestion, by a trusted source, *before* task-time issuance — a label is a fact about a
value, not about the request that moved it. Were the ledger to resolve labels from the presented
assertions, an arm that stripped the label off a sensitive payload and exfiltrated it would produce
an effect with `data_labels_touched = []`, and `realized_harm_F4` would score **no harm for exactly
the attack it exists to catch**. The ledger would be recording the attacker's own account of what it
touched, which is the same category of error red line 4 forbids for digests.

Every argument value is looked up, not one nominated payload field — a sensitive value carried in a
field nobody declared as *the* payload would otherwise be touched invisibly. `data_labels_touched`
is the union of what was found; the two singular fields name the **governing** payload, the most
restrictive label present under row 4's total order. This is sealed instrument knowledge, but it is
**not `τ_gt`**: no arm and no agent is ever handed a directory, and red line 5 is untouched.

## Consequences

- ADR 0009's category (c) is **closed**. The three named fields have constructions; nothing in the
  study still says "deferred to the F4 decision".
- F3, F4 and F5 become scoreable, taking the study from one-and-a-bit families to all five.
- `INV.label_assertions_digest` stops being a placeholder and starts binding the presented set.
- **G-15 becomes adjudicable**, because `A†` can now be tested rather than asserted: run an OAuth arm
  with and without the monitor and the dagger is either reproduced or refuted.
- Six new domain tags are permanently in service; the family assertion keeps a seventh honest.
- Two new trusted key roles exist in provisioning, injected as start-up configuration exactly as
  ADR 0019 injects the identity plane. Private halves are never written to disk (ADR 0007).
- **No frozen row moves.** Rows 4/6/10 are read, not amended; Ω, Γ, the registry and the policy
  document are untouched; no existing fixture's outcome changes (verified by regeneration).

`[DESIGN]` throughout. §F.2 names the six inputs to `authz_context_hash` and §A.6 names the join;
the constructions over them are this project's, consistent with ADR 0003/0009/0016/0018 and with no
external mandate.
