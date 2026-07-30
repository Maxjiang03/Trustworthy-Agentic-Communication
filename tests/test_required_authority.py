"""Regression suite for server-side `R` (SS A.5; EXP1 STEP 5).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. The property under test is SS A.5's: `R` is computed server-side
from the concrete request and NEVER from an agent-supplied authority
declaration.
"""

import pytest

from src.sut.protocol.required_authority import (
    SERVER_POLICY,
    RequiredAuthorityError,
    required_authority,
)


class TestConcreteRequests:
    def test_resource_argument_tools(self):
        assert required_authority("calendar.read", {"resource": "calendar/work"}) == frozenset(
            {("calendar.read", "calendar/work")}
        )
        assert required_authority(
            "notes.write", {"resource": "notes/project", "content": "x"}
        ) == frozenset({("notes.write", "notes/project")})
        assert required_authority("notes.delete", {"resource": "notes/project"}) == frozenset(
            {("notes.delete", "notes/project")}
        )

    def test_mail_send_resource_is_fixed_by_server(self):
        args = {"to": "a@example.test", "subject": "s", "body": "b"}
        assert required_authority("mail.send", args) == frozenset({("mail.send", "mail/outbox")})
        # Not even a caller-supplied "resource" argument moves it (negative arm).
        assert required_authority("mail.send", dict(args, resource="mail/other")) == frozenset(
            {("mail.send", "mail/outbox")}
        )

    def test_the_resource_argument_does_change_R(self):
        # Positive contrast for the ignore-declarations test below: the ONE
        # designated argument is exactly what does move R.
        work = required_authority("calendar.read", {"resource": "calendar/work"})
        personal = required_authority("calendar.read", {"resource": "calendar/personal"})
        assert work != personal


class TestAgentDeclarationsHaveNoEffect:
    def test_declared_scope_fields_are_ignored(self):
        base = {"resource": "notes/project", "content": "x"}
        baseline = required_authority("notes.write", base)
        for declaration in (
            {"scope": "mcp.invoke mcp.admin"},
            {"declared_scope": [["mail.send", "mail/outbox"]]},
            {"authority": "everything"},
            {"R": []},
        ):
            declared = dict(base, **declaration)
            assert required_authority("notes.write", declared) == baseline, (
                f"agent-supplied {sorted(declaration)} changed R"
            )

    def test_the_ignore_is_not_vacuous(self):
        # The same mutation applied to the DESIGNATED argument does change R,
        # so the test above cannot be passing because R ignores everything.
        base = {"resource": "notes/project", "content": "x"}
        moved = dict(base, resource="notes/meeting")
        assert required_authority("notes.read", base) != required_authority("notes.read", moved)


class TestFailClosed:
    def test_unknown_tool(self):
        with pytest.raises(RequiredAuthorityError):
            required_authority("shell.exec", {"cmd": "rm"})

    def test_missing_resource_argument(self):
        with pytest.raises(RequiredAuthorityError):
            required_authority("calendar.read", {})

    def test_non_string_resource(self):
        with pytest.raises(RequiredAuthorityError):
            required_authority("notes.read", {"resource": ["notes/project"]})

    def test_malformed_or_foreign_root_resource(self):
        with pytest.raises(RequiredAuthorityError):
            required_authority("notes.read", {"resource": "notes/project/extra"})
        with pytest.raises(RequiredAuthorityError):
            # well-formed grammar, wrong root for this tool
            required_authority("notes.read", {"resource": "calendar/work"})

    def test_policy_covers_exactly_the_five_omega_tools(self):
        assert set(SERVER_POLICY) == {
            "calendar.read",
            "notes.read",
            "notes.write",
            "notes.delete",
            "mail.send",
        }
