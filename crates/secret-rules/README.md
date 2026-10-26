# secret-rules

The single definition of the `{{ck-secret:<label>}}` placeholder, its key
location rules, host/port/path matching, response scrubbing and the audit
record, shared by AFT and (later) basal. The crate has no AFT dependency and no
I/O except `scrub::Scrubber` state.

Every rule below is exercised by committed JSON vectors under `vectors/`; the
vectors are the acceptance artifact, the Rust tests only drive them.

| Module | Spec item | What it owns |
| --- | --- | --- |
| `placeholder` | P1 | parsing, scanning, prefix detection, the single definition every other module uses |
| `location` | P2, P4 | `bearer` / `header` / `query` / `json` locations, refusals, request evaluation |
| `material` | P3 | key admissibility and per-location encoding |
| `target` | M1, M2, M4 | host/scheme/port matching, path normalization, origin/absolute form, CONNECT authority |
| `redirect` | M3 | re-evaluation of every hop |
| `scrub` | S1, S2 | encodings of a key and a streaming scrubber with an overlap window |
| `audit` | A1 | audit record v1 |

Vector file names are the contract: each group has committed inputs and
expected outputs, so a behavior change shows up as a vector diff rather than
as a silently rewritten test.

`audit::AuditRecordV1` deliberately keeps `origin` as an opaque string the
caller renders (a task id or `<fetch call id>#<hop>`); the crate never sees a
URL, a query string or a body, so no record field can hold key bytes.
