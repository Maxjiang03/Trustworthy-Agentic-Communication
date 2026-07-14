"""The INSTRUMENT (measurement harness).

Observes and scores the system under test. Imports `src.sut`; the reverse
import is forbidden (CLAUDE.md red line 6). Holds the sealed ground truth;
`tau_gt` is oracle-only and no SUT principal may read it (red line 5).
"""
