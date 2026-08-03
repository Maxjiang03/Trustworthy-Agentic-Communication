"""The freshness window `Delta`, SUT-side (ADR 0027, `frozen_parameters` row 3).

**One window, three consumers, no exceptions.** ADR 0027 fixes `Delta = 60 s`
and binds it to the `jti` replay cache TTL, the DPoP proof `iat` acceptance
window, and INV freshness at the boundary. That single-source rule is the whole
point of the decision: gate **G-14** attaches the same authenticated-request-ID
cache to `B2-DPoP` and to `B3` and compares them, so if the two arms ran under
different windows any difference G-14 observed could be an artifact of window
asymmetry rather than of the mechanisms -- a confound introduced by the
apparatus, in the gate whose entire purpose is attribution.

This module exists so that rule is **structural** rather than a convention
three call sites are trusted to remember. It is deliberately named for the
window rather than for any one of its consumers, and it holds nothing else.

**Why a SUT-side constant rather than an injected one.** `src/sut/` may never
import `src/harness/` (PROJECT_RULES.md red line 6), so the frozen document cannot be
read from here. The value is declared once on this side and a harness test
asserts it equals what `docs/frozen_parameters.md` records -- the same
agreement-not-shared-code pattern ADR 0016 drew for `Omega`/`Gamma` and
ADR 0015 rule 4 draws for the AS's key derivations. An amendment to row 3 that
forgot this constant fails that test rather than silently leaving the code and
the frozen record disagreeing.

**The injectable-clock condition travels with the window.** Every consumer of
`Delta` takes `now` as a parameter and none reads a wall clock internally, so
an over-window fixture advances the injected instant instead of sleeping.
A fixture that established over-window behaviour by waiting would add `Delta`
per repetition to a campaign specified at >= 200 repetitions per configuration
-- hours of wall-clock time measuring nothing -- and would make the suite's
runtime a function of `Delta`, so a later amendment would silently change how
long the experiment takes.

`Delta` is an **apparatus constant chosen for comparability**, not a security
recommendation: nothing in this work claims 60 s is the right window for a
deployment.
"""

# `frozen_parameters` row 3, ADR 0027. Anchored to RFC 7519 SS 4.1.4/SS 4.1.5,
# which allow "some small leeway, usually no more than a few minutes" for clock
# skew; 60 s sits at the conservative end. RFC 9449 leaves the DPoP proof
# window to the server, so no specification fixes it for us.
DELTA_SECONDS = 60

# The G-9 replay-cache budget, frozen in the same row: 2^16 entries, and
# **fail-closed on overflow** -- an insertion that cannot be recorded is a
# denial, never an admission and never a silent eviction of an unexpired entry.
REPLAY_CACHE_CAPACITY = 65536


def is_fresh(now: int, issued_at: int, window: int = DELTA_SECONDS) -> bool:
    """`|now - iat| <= Delta`, the rule all three consumers share.

    Symmetric on purpose: a timestamp from the future is as much a freshness
    failure as a stale one, and RFC 7519's leeway allowance is two-sided
    because the skew it covers has no preferred direction.
    """
    return abs(now - issued_at) <= window
