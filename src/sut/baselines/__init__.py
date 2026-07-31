"""The SS E.1 baseline ladder -- all nine arms.

    B0                     `b0.B0Arm`                        no delegation protection
    B1                     `b1.B1Arm`                        static API key
    B2-broad-noexchange    `b2_broad.B2BroadNoExchangeArm`   OAuth, broad, no exchange
    B2-exchange-broad      `b2_broad.B2ExchangeBroadArm`     + XCHG, scope unchanged
    B2-exchange-task       `b2_exchange_task.B2ExchangeTaskArm`   + XCHG narrowed to `C_i`
    B2-exchange-task-DPoP  `b2_dpop.B2ExchangeTaskDPoPArm`   + DPoP holder binding
    B-cap                  `b_cap.BCapArm`                   offline attenuation, bearer
    B3                     `b3.B3Arm`                        the full control layer
    B3+                    `b3_plus.B3PlusArm`               + bounded `jti` cache

Five of them receive per-hop `C_i` and are the strong baselines gate G-13
adjudicates: `B2-exchange-task`, `B2-exchange-task-DPoP`, `B-cap`, `B3`, `B3+`.

**Configurations, not copies.** Only four decision paths exist -- `B0`'s
constant, `B1`'s equality check, the OAuth boundary, and the capability
`CapabilityDecisionPath` -- and every arm is a configuration of one of them, declared as data (the SS E.5 bitmask, plus the
ADR 0029 ladder attributes on the OAuth family). What an arm overrides is
what its SS E.1 row says it does differently, and nothing else.

The SS E.6 matched ablations are **not** built here; each is `B3` with exactly
one conjunct disabled, and the `disabled` seam they use is bound to a declared
arm identity so `B3` proper can never silently carry one.
"""
