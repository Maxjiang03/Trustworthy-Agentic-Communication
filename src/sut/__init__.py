"""The MEASURED system (system under test).

Protocol substrate, authorization stack, capability layer, baseline ladder,
and deterministic agent mocks. MUST NEVER import from `src.harness`; the
dependency is one-way (PROJECT_RULES.md red line 6). No SUT principal may ever read
the oracle-only ground truth `tau_gt` (red line 5).
"""
