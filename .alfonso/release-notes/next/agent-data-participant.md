# Agent-data participant groundwork (off by default)

AFT has an off-by-default implementation of portable plain-file undo history
and named checkpoints, registry-based checkout rebasing, strict destination
baseline checks, bounded session snapshots, and the `agent-data/v1` protocol
core. It uses engram's session door and verifies authenticated stream digests.

The daemon catalog does **not** advertise this participant. Agent moves do not
depend on AFT until an operator enables it after the remaining daemon session
fence and atomic publication integration have been completed and verified.
Background processes, replay ledgers, permissions and indexes remain local.
