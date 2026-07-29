"""Resource-server-side authorization at the MCP boundary (gate G-4 Phase 2).

**Scope note.** This package's earlier docstring said the OAuth 2.1
Authorization Server would live here. **ADR 0015 placed the AS at
`src/sut/oauth_as/`** instead, so this package is now the *other* side of that
wire: the MCP boundary's own token validation and effective-authority
computation. It **MUST NOT import `src/sut/oauth_as/`** (ADR 0015 rule 3) --
agents and resource servers reach the AS only over the wire, and the boundary
holds only the AS **public** key, delivered from sealed configuration.

What lives here is limb **L2** of the G-4 pass criterion: the boundary computes
`Allowed(AT_i)` = `expand(AT_i.authorization_details)` intersected with the
OAuth-resource plane (`aud` names this RS, `scope` covers the request), so both
layers are enforced and neither alone can admit what the other denies.

What deliberately does **not** live here: the general `R subset-of C_n`
pre-execution rule and G-13's `Allowed(AT_i) = C_i` equality across baselines.
Gate G-2's report flagged `R subset-of C_n` as untested and owned by G-13, and
Phase 2 does not annex it.
"""
