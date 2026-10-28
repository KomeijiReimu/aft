## Watch delivery gaps are no longer silent

When a stalled connection overflows the reliable-notification retry buffer, AFT retains a watch delivery-gap warning if it cannot prove that the evicted match notice is recoverable. The warning survives restart, uses the watch's exact-version acknowledgement, and points to retained task output. A warning alone does not consume a once-watch.

Dispatch health exposes transport-copy evictions separately from outstanding watch gaps and known missing occurrences, and remains degraded until outstanding gaps are acknowledged. Recoverable watch snapshots and task completions are not counted as missing matches.
