## Background task retention maintenance

- Persisted bash-task GC now keeps a deadline-ordered index for metadata grace
  expiry and undelivered-result abandonment. Each maintenance request selects
  at most 128 deadline candidates directly, rather than waiting for a directory
  cursor to reach them among retained history.
- Shared-store validation advances at most 128 directory entries per minute;
  small stores start at most one validation lap per ten minutes. Deadline work
  is not held behind that pacing. A bounded validation cursor still discovers
  foreign metadata edits, missing worktrees, and process/cleanup-owner changes.
- The 24-hour metadata grace, seven-day abandonment test, replay and live-process
  safeguards, retained artifacts, and deletion rules are unchanged. GC continues
  to use the owning SQLite connection; it does not open a separate database.
- Each task's modification grace uses its examination time, so a completion
  acknowledged during a sweep keeps its saved output. Future modification times
  are conservatively retained rather than treated as expired.
