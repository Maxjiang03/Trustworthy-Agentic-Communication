"""Holder-binding verification: the HTC chain and the INV assertion (gate G-11).

Implements `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` SS F.2 and SS F.2.1. The
verifier is the **instrument**, so it lives under `src/harness/`: it recomputes
every digest it checks from raw evidence and never consumes a value a system
under test computed (D13/D21, PROJECT_RULES.md red line 4).

Why the HTC exists at all `[VERIFIED]`: Biscuit's per-block signatures use
single-use keypairs that prove blocks are correctly chained, and only the
authority block is signed by a well-known multi-use key. Those block keys do
**not** authenticate *which principal* performed each attenuation. Holder
binding needs delegate *identity*, so the HTC chain is signed by each hop's
identity key and carries `next_holder_pubkey`, and the terminal INV must be
signed by the key the last HTC names -- chaining back to issuance. This is a
project construction layered on Biscuit and is described as such.

Modules:

* `at_digest`  -- `INV.access_token_hash` (ADR 0018), closing ADR 0009's
  category (c) for that field.
* `registry`   -- the SS F.2.1 identity-plane registry (ADR 0019): `actor_of(.)`
  to exactly one principal, principal to exactly one holder key.
* `holder_binding` -- the HTC/INV objects and the full SS F.2 verification, one
  named check per MUST with its own reason code.
* `label_context` -- the six ADR 0030 constructions (`payload_digest`,
  `authz_context_hash`, `label_assertions_digest`, and the three artifact
  signing domains), closing ADR 0009's LAST category (c) fields.

Commitments are **reused, never reinvented**: `prefix_hash`,
`child_block_hash` and `INV.capability_hash` all come from
`src/harness/oracle/commitment.py`, the ADR 0003 construction gate G-1 verified
and G-2 used. There is no second notion of "the prefix" anywhere in this package.
"""
