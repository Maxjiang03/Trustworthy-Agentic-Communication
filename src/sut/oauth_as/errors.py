"""The rejection catalogue of `smoke/g4/DESIGN.md` SS 6, as code.

Every refusal the AS can emit is one of these, carrying the **exact** error code
and HTTP status the catalogue fixes. Nothing here invents a code: each is either
an OAuth 2.1 SS 3.2.4 code, an RFC 8693 SS 2.2.2 code, an RFC 9396 SS 5/SS 6
code, or an RFC 9449 SS 5/SS 8 code, and the catalogue row is named in the
`row` field so a test can assert per row.

Two rows carry more than a body: `invalid_client` when the client used the
Authorization header is **401 with `WWW-Authenticate`** (OAuth 2.1 SS 3.2.4),
and `use_dpop_nonce` carries a `DPoP-Nonce` header (RFC 9449 SS 8).
"""

from dataclasses import dataclass, field

# Error codes, each traceable to a specification section.
INVALID_CLIENT = "invalid_client"  # OAuth 2.1 SS 3.2.4
UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"  # OAuth 2.1 SS 3.2.4
INVALID_REQUEST = "invalid_request"  # OAuth 2.1 SS 3.2.4; RFC 8693 SS 2.2.2
INVALID_AUTHORIZATION_DETAILS = "invalid_authorization_details"  # RFC 9396 SS 5/SS 6
INVALID_TARGET = "invalid_target"  # RFC 8693 SS 2.2.2; RFC 8707 SS 2
INVALID_DPOP_PROOF = "invalid_dpop_proof"  # RFC 9449 SS 5
USE_DPOP_NONCE = "use_dpop_nonce"  # RFC 9449 SS 8
INVALID_TOKEN = "invalid_token"  # RFC 9068 SS 4 (resource-server side)


@dataclass
class OAuthError(Exception):
    """A catalogue refusal. Raising one guarantees no token was issued."""

    code: str
    row: str  # the SS 6 catalogue row this refusal implements
    description: str = ""
    status: int = 400
    headers: dict[str, str] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.code} ({self.row}): {self.description}"

    def body(self) -> dict[str, str]:
        """The OAuth 2.1 SS 3.2.4 JSON error body."""
        payload = {"error": self.code}
        if self.description:
            payload["error_description"] = self.description
        return payload


def invalid_client(description: str, *, used_authorization_header: bool = False) -> OAuthError:
    """SS 6 row 1. 401 + `WWW-Authenticate` iff the client used the Authorization header."""
    if used_authorization_header:
        return OAuthError(
            INVALID_CLIENT,
            "client-authentication",
            description,
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="aasc-as"'},
        )
    return OAuthError(INVALID_CLIENT, "client-authentication", description)
