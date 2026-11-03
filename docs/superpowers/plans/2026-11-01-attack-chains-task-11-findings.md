# Task 11 review findings, fix round 1

The review found that the brief's pseudocode is itself unsafe, so replace `merge_joiners` with the algorithm below. It overrides the brief. A Python port of the old code proved these holes.

## Why (Critical)

C1. One address merges two stager clouds. s0..s4 name S, t0..t4 name T; add loose x naming S and T: 1 campaign of 11. The first value makes a group with x, and the second value's addresses are then all "lone" and join it, so the guard never runs. Same if x sits in a hard group: {a1,a2} with a1 naming S and T absorbs both clouds. An honest script listing two mirrors does it too.

C2. An absorbed singleton counts towards K, so sort order decides a merge. Groups A and B of three each: a1, a2, b1 name V; b2, b3 name T: 2 campaigns. Add x naming T and V: x joins B on T, B reaches 2 on V, and they merge. Rename T to Z so it sorts after V, and they stay apart. A bridge also works: T={b1,x}, U={x,l1,l2}, V={a1,a2,l1,l2} merges A and B.

## The algorithm (Ruling)

Definitions, after the hard and guarded soft phases, on `p.guard = Some(k)`:
- A **group** is a component of two or more addresses.
- A **loose** address is in no group.
- Membership used for counting is always taken BEFORE any absorption. Nothing absorbed ever lifts a count.

Steps:

1. **Clouds.** Each value's loose addresses form a value cloud. Two value clouds connect when the loose addresses naming both number at least `max(k, smaller_cloud / 10)`. Clouds are the connected components of that graph. So a stager and key shared by 37 of 163 addresses are one cloud, and one or two forged addresses are not a bridge.
2. **Assign.** A loose address in two unconnected clouds goes to the larger one, ties by smallest value key. It bridges nothing. A cloud left with one address is a lone address.
3. **Blocks.** Groups and clouds of two or more addresses are blocks. Blocks A and B connect when some single value is named by at least `k` distinct addresses of A and at least `k` distinct addresses of B, using pre-absorption membership. Take connected components over the original blocks, with no fixpoint and no counting across a merge. So there is no cascade and no order dependence.
4. **Lone addresses join once.** For each lone address, tally per merged block the distinct block members sharing any value with it, across all its values. It joins the block with the highest tally, ties by smallest root IP text. A lone address with no tally stays loose. Lone addresses never count for step 1 or 3.
5. **Edges.** For each value, per final group: a star from the value's naming addresses in that group to that group's oldest naming address, `merged = 1`. Between groups: one `merged = 0` edge from each other group's anchor to the value's oldest anchor. Loose naming addresses count as their own group. This replaces the single value-wide star, so every member has evidence inside its campaign.

The result is a pure function of the partition of addresses and the value sets: renaming values or reordering rows must not change membership.

## Findings

C1, C2: fixed by the above. Add regression tests with exact membership:
- `one_address_on_two_clouds_merges_nothing`, and with x in a hard group.
- `two_addresses_on_two_large_clouds_merge_nothing` (2 of 5 is `max(2,0)`, so use clouds of 30 to prove the 10 % rule).
- `a_stager_and_its_key_form_one_cloud` (37 of 163).
- `a_lone_address_does_not_lift_the_count`, for both T<V and V<Z namings.
- `the_bridge_through_loose_addresses_does_not_merge_b`.
- `renaming_values_keeps_the_partition`: a seeded random input, values renamed by a random permutation, partition identical.

I1. Joiner edges have no volume cap. Two addresses can name 256 fresh stagers per body. Fix: `MAX_JOINERS_PER_IP = 64`, newest kept, as `MAX_SHAPES_PER_IP` does, and report drops in `excluded`. Add a limit to the Evidence table, with a "first N" note.

I2. `value_order_does_not_change_the_outcome_across_runs` only reverses input rows, and `a_joined_singleton_does_not_add_to_the_guard` uses one value. Replace both with the tests above.

Docs: `docs/detection.md:409-411` and `src/admin/glossary.rs:79` must state the final rule, and that an attacker with two addresses in each of two groups can still merge them, shown as claimed.

Minor: `src/store/campaigns.rs:1096`: rewrap the doc comment.

Also: `joiner_edges` counts merged edges only, and the Evidence head must say so when more rows are listed.
