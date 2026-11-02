# Task 11 fix round 2: a simpler rule

A forgery search broke round 1 again: two addresses can still join two groups, and one fresh value bypasses the 10 % rule. Each patch has added machinery and exposed a new hole, because a claimed string is being allowed to merge existing evidence. Stop patching. This replaces steps 1-5 of `task-11-findings.md`.

## The rule (Ruling)

**Joiners only ever group addresses that have no campaign of their own. They never merge, grow or shrink an existing group.** A group here is a component of two or more addresses after the hard and guarded soft phases. A claimed string can never change a campaign that stands on real evidence. The chain still shows the link across campaigns, which is what the Chains views are for.

On `p.guard = Some(k)`:

1. **Values.** Keep only values named by at least two addresses, after the fan-out rule and `MAX_JOINERS_PER_IP`, which becomes 16. For each value, take its loose namers: addresses in no group.
2. **Connect values.** Two values connect when the loose addresses naming both number at least `max(k, ceil(larger_value_loose_namers / 10))`. Use the LARGER value, so a fresh small value bridges nothing. Clouds are the connected components. Clouds with identical member sets are one cloud, so no name can tie-break them.
3. **Assign.** A loose address in several clouds goes to the largest. Ties compare the sorted member lists, smallest first. Never compare value names.
4. **Split.** Within each cloud, union assigned addresses that share a value of that cloud. Each component of two or more is a new group. A component of one stays loose. So every group's members share evidence.
5. **Edges.** For each value, per final group: a star from its naming addresses in that group to the group's oldest naming address, `merged = 1`. Between different groups or loose addresses naming it: one `merged = 0` edge from each other group's anchor to the value's oldest anchor. An existing group's members therefore get `merged = 0` edges only.

There is no group merging, no lone-address absorption and no fixpoint. Remove that code, including the K-in-each counting.

## Purity and cost (Important 5, 6)

- The cap's tie order must not reach a value name and must not walk address sets per comparison. Rank each value's address set once (sort the distinct sets, take the index), then sort by (time, rank). Values tied on both have identical address sets, so which is dropped changes nothing.
- Keep it near linear. Pair counting is bounded by 16 values per address.

## Chains need the same threshold

`src/store/chains.rs` `connect` connects a joiner pair from two addresses, so two addresses naming S and T fuse two operators' chains. Use the same rule: a pair connects when the addresses naming both number at least `max(2, ceil(larger_joiner_addresses / 10))`. Keep the 64-joiner skip. Update the Chains tests; a pair seen by 37 of 163 addresses still connects.

## Tests

Assert exact membership.

- `joiners_never_merge_groups`: groups of 3, with 2, 3 and all members naming one value: still two groups, with `merged = 0` edges.
- `joiners_never_grow_a_group`: a loose address and a group on one value: the group is unchanged, and the address stays loose.
- `two_addresses_join_nothing`: loose x and y naming values of two groups: groups unchanged, x and y form a group of their own only if they share a value.
- `a_hard_pair_joins_nothing`: x and y as a hard group do the same.
- `a_fresh_value_does_not_bypass_the_tenth`: clouds of 1,000, Q = {x, y}, x and y on all three: clouds stay apart.
- `a_stager_and_its_key_form_one_cloud`: 37 of 163.
- `one_address_on_two_clouds_merges_nothing`.
- `a_split_cloud_leaves_no_group_without_shared_evidence`: the reviewer's case: `V1={0,2,3}`, `V2={1,2,3}`, `D0={2,10,11,12,13}`, `D1={3,12,13,14,15}`, `D2={10,11,14,15,16}`: no group holds members sharing no value.
- `identical_clouds_tie_on_no_name`: 13 addresses with two unconnected clouds of 11 values each, sets of three consecutive addresses, the second cloud stepping 5 modulo 13: swapping name prefixes keeps the partition.
- `the_cap_never_reads_a_name`: tied timestamps, renamed values, same partition.
- `renaming_values_keeps_the_partition`: keep it.
- Chains: `two_addresses_on_two_large_joiners_fuse_nothing`.

Remove tests that assert the old merges.

## Docs

`docs/detection.md`, `src/admin/glossary.rs:79` and the comments at `src/store/campaigns.rs:1142`, `:1181` must state the new rule: joiners group only addresses with no campaign, never merge campaigns, and the chain shows links across campaigns. Remove the old limit about two addresses in each group. The known limit now: forged addresses need at least a tenth of a large value's namers to connect two values.
