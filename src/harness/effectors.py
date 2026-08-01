"""Harness-held effector: the implementation behind the SUT tool server's seam.

The SUT's tool stubs (`src/sut/protocol/mcp_tools.py`) call an injected
effector; this is what the runner injects. It holds the `LedgerWriter` --
the only write path into the exclusive-share ledger file (gate G-7) -- and
records one `EffectEvent` INTENT per call. The SUT never sees the writer, so
no SUT code path can amend or delete what was recorded (D21, SS F.1).

`effect_request_digest` is `H_JCS` over the arguments the tool actually acted
on, computed HERE, ledger-side -- never accepted from the SUT (red line 4).

The same rule governs ADR 0030's three label fields: `data_labels_touched` is
resolved from the harness's own **ingestion-time** directory over the values the
tool actually acted on, never from the `LabelAssertion`s the request carried. An
arm that stripped a label off a sensitive payload would otherwise produce an
effect touching nothing, and `realized_harm_F4` would score no harm for exactly
the attack it exists to catch.
"""

import secrets
import time

from src.harness.effect_ledger import LedgerWriter
from src.harness.oracle.jcs_digest import h_jcs
from src.harness.policy import label_directory
from src.harness.schema import EffectEvent


class LedgerEffector:
    """Records each effect intent into the harness-held ledger."""

    def __init__(
        self,
        writer: LedgerWriter,
        *,
        audience: str,
        principal: str,
        correlation_provider,
        labels: label_directory.LabelDirectory | None = None,
        label_order: tuple[str, ...] = (),
    ) -> None:
        self._writer = writer
        self._audience = audience
        self._principal = principal
        self._correlation_provider = correlation_provider
        # Defaults to the empty directory, so a run that declares no labelled
        # values behaves exactly as before ADR 0030.
        self._labels = labels if labels is not None else label_directory.EMPTY
        self._label_order = label_order

    def __call__(
        self,
        *,
        tool: str,
        action: str,
        resource: str,
        recipient: str | None,
        arguments: dict,
    ) -> None:
        payload_digest, value_id, labels_touched = self._labels.observe(
            arguments, order=self._label_order
        )
        self._writer.append(
            EffectEvent(
                effect_id=secrets.token_hex(8),
                correlation_id=self._correlation_provider(),
                tool=tool,
                audience=self._audience,
                action=action,
                resource=resource,
                recipient=recipient,
                effect_request_digest=h_jcs(arguments),
                # ADR 0030: recomputed here from the values acted on and the
                # instrument's own ingestion directory. Empty for the pilot
                # scenarios, which declare no labelled values.
                payload_digest=payload_digest,
                value_id=value_id,
                data_labels_touched=labels_touched,
                approval_ref=None,
                principal=self._principal,
                timestamp_ns=time.time_ns(),
            )
        )
