# Provenance of this directory

Copied byte-for-byte from the Plexus repository (`cortexkit/plexus`),
commit `377e1874`, directory
`crates/plexus-core/tests/fixtures/gh_shim_wire/`:
`README.md`, `requests-contract/` (144 vectors) and `replies-contract/`
(15 vectors).

Those files are Plexus's own: each one is proven on every Plexus test run
against the real `gh.route` facade (see the "Request and reply contract
vectors" section of the vendored `README.md`). AFT pins its gh shim tests
to them: the shim's pre-signing round trip once passed against a stand-in
that accepted the `gh_route_schema` envelope field live Plexus refused, so
AFT pins its gh shim tests to these vectors and the stand-in can no longer
be more lenient than Plexus's real route. Re-copy from a newer Plexus commit to pick up contract changes,
and keep this file's commit reference in step.
