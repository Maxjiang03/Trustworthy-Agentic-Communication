"""Trustworthy Agentic Communication testbed.

Two sub-packages with a one-way dependency: `sut` (the measured system) and
`harness` (the instrument). `sut` must never import from `harness`
(CLAUDE.md red line 6).
"""
