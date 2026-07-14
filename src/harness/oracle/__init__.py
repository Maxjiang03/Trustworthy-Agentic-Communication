"""Independent offline oracle — TODO (design Part I).

reference_allow / observed_forwarded / admission_breach / realized_harm /
false_block / log_integrity_failure. The oracle NEVER reads a SUT-computed
verdict or digest; it recomputes from raw evidence, sealed truth, and the
external effect ledger (CLAUDE.md red line 4).
"""
