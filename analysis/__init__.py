"""The pre-registered statistical procedure, as code (EXP6 STEP 9).

Part H step 3 seals *"design document, implementation commit, **oracle code,
analysis code**, all configuration …"*. This package is the analysis code, and
until this block it did not exist — `analysis/` held a single `.gitkeep`, so one
of the artifacts the seal names had nothing to hash.

Two modules, and the split is the one §E.5 insists on:

* `security` — **exact counts and rates only**, plus a nondeterminism check.
  There is no interval estimator in it, and its absence is asserted by test: a
  fixed author-constructed suite has no random-sampling population, so a
  confidence interval on `blocked/total` would invite a reader to treat this
  corpus as a sample of attacks, which it is not.
* `latency` — the **only** sampled quantity, with median / p95 / IQR and the
  **95% bootstrap CI** ADR 0026's decision rule reads. The rule returns
  *stands* / *retracted* **and** the interval, never a bare number.

**Nothing here measures anything.** These modules have no clock, no timer and
no import of the runner: they take samples as plain numbers from a caller. G-3
has not run and `frozen_parameters` row 9 (the sealed measurement platform) is
not locked, so a real timing fed in here would both violate EXP6 forbidden
action 1 and produce a number ADR 0025 says cannot count. The tests use
**synthetic** samples whose answers are constructed.
"""
