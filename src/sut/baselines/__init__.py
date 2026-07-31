"""The SS E.1 baseline ladder.

Built: `b0.B0Arm`, `b2_exchange_task.B2ExchangeTaskArm`, `b_cap.BCapArm`,
`b3.B3Arm` -- the unprotected control plus the three arms that receive per-hop
`C_i`, which are the ones gate G-13's criteria can reach.

Not built: `B1`, `B2-broad-noexchange`, `B2-exchange-broad`,
`B2-exchange-task-DPoP`, `B3+`, and the SS E.6 matched ablations. Each plugs
into the same `base.Arm` seam when its own task builds it; nothing here assumes
their absence.
"""
