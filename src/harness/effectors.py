"""Harness-held effector: the implementation behind the SUT tool server's seam.

The SUT's tool stubs (`src/sut/protocol/mcp_tools.py`) call an injected
effector; this is what the runner injects. It holds the `LedgerWriter` --
the only write path into the exclusive-share ledger file (gate G-7) -- and
records one `EffectEvent` INTENT per call. The SUT never sees the writer, so
no SUT code path can amend or delete what was recorded (D21, SS F.1).

`effect_request_digest` is `H_JCS` over the arguments the tool actually acted
on, computed HERE, ledger-side -- never accepted from the SUT (red line 4).
"""

import secrets
import time

from src.harness.effect_ledger import LedgerWriter
from src.harness.oracle.jcs_digest import h_jcs
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
    ) -> None:
        self._writer = writer
        self._audience = audience
        self._principal = principal
        self._correlation_provider = correlation_provider

    def __call__(
        self,
        *,
        tool: str,
        action: str,
        resource: str,
        recipient: str | None,
        arguments: dict,
    ) -> None:
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
                payload_digest=None,
                value_id=None,
                data_labels_touched=[],  # pilot scenarios carry no LabelAssertion (rows 4/6 UNSET)
                approval_ref=None,
                principal=self._principal,
                timestamp_ns=time.time_ns(),
            )
        )
