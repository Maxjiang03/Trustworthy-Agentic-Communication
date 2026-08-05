# Work specifications — the retrospective record of how each block was built

The documents in this directory are the specifications under which each block of the
implementation was built: one per gate pass or experimental block, from the repository skeleton
(`BOOTSTRAP_TASK.md`) through the held-out corpus (`archive/exp7-subcases-and-heldout/`). They
are retained in the submitted artifact for two reasons:

1. **The implementation cites them by step number.** Source files, tests, gate reports and ADRs
   locate content by identifiers such as `EXP6 STEP 3` or `BOOTSTRAP_TASK STEP 2`, and those
   identifiers resolve to the step headings in these documents. Removing the documents would
   leave those citations dangling.
2. **They are the engineering record.** Each carries the scope of its block, the acceptance
   standard it was held to, and the constraints it worked under — a forbidden-actions table with
   a reason per row, and the self-check every block had to answer. Read together they record
   what each piece of the apparatus was and was not permitted to do at the time it was built.

Each `archive/*/MANIFEST.md` records the SHA-256 of its specification **as archived at the time
of execution**, together with the standing label: these are **retrospective records, not
pre-registration evidence**. The copies here differ from those archived bytes in exactly one
recorded way: the launch plumbing (integrity self-checks, and the sentences that addressed an
executor rather than a reader) was removed after the fact, with every removed line enumerated
and category-checked by `tools/workplan/verify_prune.py`; the archived bytes remain retrievable
at the commit each MANIFEST describes. No surviving line was reworded, and no step identifier
changed.
