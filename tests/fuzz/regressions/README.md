# Fuzz Regressions

`tests/fuzz/regressions/` is for minimized repro inputs that demonstrate a
real bug the fuzz suite found and that we want to keep permanently wired into
the relevant harness. Store each repro under the matching per-harness
directory, for example `tests/fuzz/regressions/token/` or
`tests/fuzz/regressions/paserk_pie/`.

What belongs here:
- Inputs that previously crashed the process, tripped an unexpected assertion,
  produced an unexpected success path, or otherwise escaped the harness's
  documented allowlist/invariant checks.
- Files that are already minimized enough to be readable during triage or
  cheap to keep in the seed corpus long-term.

What should stay in a normal corpus instead:
- Inputs that are valid edge cases rather than bug repros.
- Seeds added only to improve coverage or exercise a parser branch.
- Non-crashing malformed inputs that are fully covered by an existing harness
  contract and do not represent a new bug class.

Naming guidance:
- Let the directory carry the harness ownership.
- Name the file after the bug class and an optional short discriminator.
- Use stable, descriptive names such as:
  - `invalid-padding-overread.bin`
  - `body-mutation-accepts.bin`
  - `short-signature-panics.bin`

Wiring a repro into a harness:
1. Add the file under `tests/fuzz/regressions/<harness>/` using the naming
   scheme above.
2. Add it to the relevant harness seed list with `@embedFile`, for example:

```zig
const seeds = [_][]const u8{
    @embedFile("corpus/token/header_only.bin"),
    @embedFile("regressions/token/invalid-padding-overread.bin"),
};
```

3. Keep the regression in the same harness that originally exposed the bug
   unless another harness reaches the boundary more directly.
4. If the repro stops being special because the input is now just a useful
   parser seed, move it into `corpus/<harness>/` and remove the regression
   label from the filename.
