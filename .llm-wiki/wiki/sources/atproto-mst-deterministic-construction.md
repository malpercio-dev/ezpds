---
type: source
title: "ATProto MST determinism: collect-rebuild pattern"
slug: atproto-mst-deterministic-construction
status: insight
created: 2026-06-22
updated: 2026-06-22
category: architecture
---
# ATProto MST determinism: collect-rebuild pattern
When implementing an ATProto MST, the naive recursive insert/delete approach is inherently order-dependent — building different tree shapes depending on prior insertions. The ATProto spec requires the tree structure to depend only on the key set, not insertion order. 

The fix: replace recursive insert/delete with a deterministic `from_sorted_entries` constructor that collects all entries, adds/removes the target, sorts, and rebuilds the tree bottom-up by layer. Both `insert` and `delete` now use the collect→mutate→rebuild pattern.

The `build_node` algorithm partitions entries by layer — entries at the current layer become node entries, entries below are grouped into subtrees between consecutive same-layer entries. This guarantees insertion-order independence while preserving the MST's self-balancing property via SHA-256 prefix-zero counting.

Implementation at `crates/repo-engine/src/mst.rs` (805 lines, 27 tests). Dependencies: cid 0.11, multihash 0.19, serde_ipld_dagcbor 0.6, serde_bytes 0.11.
*Category: architecture*
---
*Captured: 2026-06-22*
## Related
_Add links to related pages._