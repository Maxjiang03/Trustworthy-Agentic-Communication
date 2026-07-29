"""The pinned experiment OAuth 2.1 Authorization Server (ADR 0015, gate G-4).

Built to `smoke/g4/DESIGN.md` SS 5-7. It is a **subpackage of the measured
system**: its round-trip cost is inside the measured quantity (`delegation_cost`,
SS E.2), so it is not an instrument -- yet the instrument must never issue the
credentials it later adjudicates. Four rules travel with that placement, and all
four are tested at G-4 Phase 2:

1. **Out-of-process.** Own OS process, loopback interface only. No agent process
   ever hosts it in-process.
2. **Key isolation.** The Ed25519 signing key is derived inside the AS process
   from the sealed seed, never written to disk, never exported. Only the public
   key leaves, and it reaches the boundary from sealed configuration -- the
   profile publishes no `jwks_uri`.
3. **No agent may import this package.** Modules under `src/sut/` other than
   `src/sut/oauth_as/` MUST NOT import it; agents reach the AS over the wire.
   Without this a baseline agent could mint the very tokens the baseline is
   supposed to constrain.
4. **`src/harness/` may never import it**, notwithstanding the harness's general
   permission to import `sut`. The oracle and the G-13 verifier reimplement
   token verification independently (D13/D21).

**Not RFC 9068-conformant, by decision (DESIGN SS 8.3).** RFC 9068 SS 2.1
requires RS256 among the supported algorithms; this project signs Ed25519
everywhere with an explicit allowlist (ADR 0006). The profile uses the RFC 9068
*shape* -- `typ: at+jwt`, the required claim set, `aud` from `resource`, the SS 4
validation rules -- and no document may call it "RFC 9068-compliant".
"""
