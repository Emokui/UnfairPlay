# Contributor instructions

These rules apply to the whole repository.

## Safety and privacy

- Never commit Apple credentials, tokens, SIDB/SIDS files, personalized SINF or
  SUPF files, enrollment models, hardware identifiers, decrypted apps, private
  captures, or environment-specific absolute paths.
- Tests committed to the repository must use synthetic or public fixtures.
  Private controls belong in the opt-in workflow documented in `QA.md`.
- Keep recovery fail-closed. Do not silently accept an unknown build, selector,
  model, instruction, memory range, or control-flow edge.
- Do not describe mechanically extracted or inferred code as verified. State
  exactly how each new execution path was established.

## Recovery profiles

- A verified fallback block must match the supported `fairplayd` instruction
  stream exactly and have a focused regression test.
- Verified fallback blocks and the large mechanically extracted fallback profile
  must remain disjoint. When promoting a block:
  1. add its address as a `--seed-start` in the generation recipe in `QA.md`;
  2. regenerate the extracted profile;
  3. update the pinned block count, rejected count, and SHA-256;
  4. update external extraction geometry tests; and
  5. retain the test that rejects overlap between the two profiles.
- Do not broaden exact-build or reference-binary policy using an evaluator,
  model, or profile hash unless that hash is proven to identify the source
  binary. Preserve separate tests for policy and for block semantics.
- Generated profiles must have a reproducible command and pinned digest in the
  same pull request.

## Pull requests

- Keep changes narrow. Do not mix a new recovery path with unrelated cleanup.
- Explain the supported build and account/enrollment layout affected by the
  change. Do not claim support beyond the evidence provided.
- Include non-secret validation evidence when applicable: source build and
  binary SHA-256, model SHA-256, resulting IPA SHA-256, selector, image/page
  counts, fallback addresses used, and whether exact extracted blocks ran.
- Add a regression test that exercises the new branch. Do not rename, delete,
  or weaken an existing invariant test merely because the new change violates
  it; fix the implementation or update the generated artifact correctly.
- Before submitting, run:

  ```sh
  gofmt -w <changed-go-files>
  go test ./...
  go vet ./...
  go test -race ./...
  ```

- If private controls are available, run the complete matrix from `QA.md` and
  report only non-secret hashes and counts. State clearly when private QA was
  not run.
- Review the final diff and repository status. Do not include temporary dumps,
  generated binaries, editor files, or unrelated local changes.

