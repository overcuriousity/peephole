# Final fix wave

Fix every finding in `final-review.md`, in this directory: C1, I1-I5, M1-M18. Use the review's own suggested fix unless a ruling below says otherwise. The project does not defer findings.

## Rulings

- C1: use the window-function read in SQL for both `joiner_sightings` and `Input::read`, newest `MAX_JOINERS_PER_IP` distinct joiners per address. Add the test the review asks for, asserting row counts. This must hold on the public trap at the default record rate.
- I3: extraction becomes its own background task. The hourly tick does not wait on it, and the campaign pass runs on what has been read so far.
- I4: restrict the `src` CTEs to joiner kinds, read the newest 2,000 sources per joiner from an index on `(piece, ts)`, added in `0052_chains.sql`, which is unreleased. Check with `EXPLAIN QUERY PLAN`, and time it on the copy at `/home/user01/.cache/peephole-ac-accept/observer.db`, opened read-only or on a copy of it.
- I5: dossiers keep `body_text` and `body_b64`. State plainly in `docs/api-v1.md`, `docs/operations.md` and `CHANGELOG.md` that a dossier's raw body can hold a captured key, and that a key written line by line is not masked. Scope "never" to the `chain` and `xray` objects.
- M7: add `external` to the Chains list and the API `payload`, with docs and OpenAPI.
- M9: change the lane note to say the band is the chain's requests, across campaigns.
- M12: filter the public "Campaigns this period" tile on `joiner_edges = 0`, so public pages stay unchanged. Add a test.
- M17: state the accepted limit plainly, including that as few as two forged addresses can show two unrelated loose groups as one false campaign.

## Declined items, ruled

- Raw `value` and `urls[].url` in the API and dossiers stay, beside `defanged`: scripts and sandboxes need them, and these routes need a scoped token. Correct constraint wording in docs where it says only "Copy for sandbox" gives a raw URL.
- Request headers are not parsed. Add a line to `docs/roadmap.md` as the next item: parse header values, for payloads such as Shellshock in `User-Agent`.

## Also

The five clippy lints:
- `src/model/xray/shell.rs:1191`: rename `to_else`.
- `src/model/xray/decode.rs:940`: `is_multiple_of`.
- `src/model/xray/shell.rs:2526`, `src/store/chains.rs:3136`: plain `assert!`.
- `src/store/chains.rs:1937`: elide the lifetime.
