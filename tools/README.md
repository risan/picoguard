# Oracle tools (GPL-3.0, development only)

These programs generate and check the golden files in `tests/fixtures/golden`. They depend on
AdGuard's GPL-3.0 code (`urlfilter` v0.23.4) or drive the GPL-3.0 AdGuard Home binary, so they are
GPL-3.0 themselves (`LICENSE-GPL-3.0`). They are **never linked into picoguard**: the crate
(`MIT OR Apache-2.0`) does not depend on them, no file under `src/` is derived from them, and
`cargo test` does not run them (tests are hermetic, the golden files are committed).

| Path | What it does |
|---|---|
| `agh-oracle/` | Go program on `urlfilter` v0.23.4. Reads rule files and `input checktype [querytype]` lines and prints `... pass -` or `... block ANSWER`. `agh-oracle sample` draws the queries of the real-list test. |
| `agh-flow/` | Go program that runs the pinned AdGuard Home v0.107.79 linux/amd64 release against a scripted fake UDP/TCP upstream and records the full reply per query (`flow.expected`). Its decisions mode replays oracle queries against the binary. |
| `regen.sh` | Regenerates every golden file (`oracle`, `flow` or `all`). |
| `check-oracle.sh` | Runs every matcher case and the real lists through both `agh-oracle` and the AdGuard Home binary and compares them. |
| `sample-real.sh` | Draws the sampled queries of the real-list test (run once when the list fixtures change). |
| `split-case.sh` | Splits a `.case` file into list and query files. |

The AdGuard Home release is downloaded by `agh-flow/fetch.sh` from the GitHub release, checked
against the pinned SHA-256 (the value in the release's `checksums.txt`) and cached in
`~/.cache/picoguard-oracle/`, outside the repository.

## Case file format (`tests/fixtures/golden/cases/*.case`)

Sections: `[main]` (one per list, in order; the same engine as AdGuard's filters), `[user]` (user
rules, a list of the main engine), `[allow]` (one per allowlist, a separate engine checked first),
`[queries]` and `[deviations]`. A query line is `input checktype [querytype]`: `checktype` is the
record type checked against the rules, `querytype` the type of the original question (it shapes a
blocked answer) and defaults to `checktype`. `.expected` holds the oracle output.

`[deviations]` lines are `query => decision answer`: the queries where picoguard is expected to
differ from the oracle, with picoguard's outcome (plan D7, overlapping `$badfilter`).

## Known differences between the oracle and the AdGuard Home binary

`check-oracle.sh` ignores them; each comes from the test setup, not from matching:

- `$client=` rules: the binary sees the client 127.0.0.1, the oracle sees no client.
- `$dnsrewrite` rules: the binary rewrites, the oracle ignores them (out of scope for picoguard).
- A rule on the last line of a file without a line feed is lost by the binary's file-backed list
  storage; `agh-flow` adds the missing line feed so lists are read as in normal operation.
