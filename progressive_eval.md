# Ordered reads over non-overlapping but internally-unsorted files (ProgressiveEval)

## Problem statement

The `sort-order` branch (see `plan.md`) optimizes ordered reads when Parquet
files are **internally sorted**: DataFusion's `PushdownSort` rule +
`FileScanConfig::try_pushdown_sort` validate non-overlap via min/max
statistics and eliminate the `SortExec` entirely (`Exact`).

This plan covers the next case: data files can be **grouped into batches with
non-overlapping ranges** on the sort key, but rows *within* each file are not
necessarily sorted. Statistics alone can then only produce `Inexact` — the
files get reordered but a full global `SortExec` remains, buffering the whole
dataset before emitting anything.

Goal: sort each non-overlapping batch separately and stream the sorted batches
in turn. Wins:

- Peak sort memory bounded by the largest batch, not the whole dataset.
- First output rows after the first batch is read+sorted, not after all data.
- `LIMIT` queries terminate without ever opening later batches' files.

## Prior art / key references

- **DataFusion issue tracking ProgressiveEval upstreaming:**
  <https://github.com/apache/datafusion/issues/15191> (earlier issue:
  <https://github.com/apache/datafusion/issues/10488>)
- **Proposed (closed, unmerged) upstream implementation — PR #10490:**
  <https://github.com/apache/datafusion/pull/10490>. The core is a single
  self-contained file, `datafusion/physical-plan/src/sorts/progressive_eval.rs`
  (~1700-line diff including tests). Fetch it with:
  `gh pr diff 10490 --repo apache/datafusion`
- **InfluxData blog on the operator:**
  <https://www.influxdata.com/blog/query-optimization-progressive-evaluation-influxdb/>
  (production implementation lives in `influxdb3_core`).
- Local DataFusion checkout for reference: `../../datafusion/datafusion`
  (paths below are relative to that repo).

**We should aim to copy the ProgressiveEvalExec implementation from PR #10490
into delta-rs and reuse it exactly as-is where possible** (see Step 1). It is
generic — nothing Delta-specific — and keeping it unmodified maximizes the
chance of later deleting our copy in favor of an upstreamed version, with this
work serving as the motivating second use case for #15191.

## Why the integration point works (verified against DataFusion main, 2026-07)

These facts were verified by reading the DataFusion source; they are the
load-bearing assumptions of the design:

1. `ExecutionPlan::try_pushdown_sort` returns
   `SortOrderPushdownResult<Arc<dyn ExecutionPlan>>`
   (`datafusion/physical-plan/src/execution_plan.rs:807`). The
   `Exact { inner }` variant carries an **arbitrary plan** — the `PushdownSort`
   rule drops the `SortExec` and splices `inner` in, re-attaching any `fetch`
   via `with_fetch`. So `DeltaScanExec` can return a composite plan
   (ProgressiveEval over per-partition Sort) as its `Exact` answer. No new
   DataFusion extension point is needed.
2. `PushdownSort` runs **after** `EnsureRequirements` (the merged
   EnforceDistribution/EnforceSorting pass) — see rule ordering in
   `datafusion/physical-optimizer/src/optimizer.rs` (~lines 190–235). Nothing
   later inserts a `RepartitionExec` inside the returned subtree, so the
   batch-per-partition layout is preserved.
3. In the multi-partition pattern
   (`SortPreservingMergeExec → SortExec(preserve_partitioning) → DeltaScanExec`),
   the rule keeps the SPM after eliminating the sort — but SPM over a
   1-partition input is a plain passthrough (fast path in
   `datafusion/physical-plan/src/sorts/sort_preserving_merge.rs:332`), so it
   degenerates to a no-op above our single-partition node. The rule also
   inserts a `BufferExec` there, which is harmless/beneficial (read-ahead).
4. PR #10490's `ProgressiveEvalExec::compute_properties` clones the **input's**
   equivalence properties. With `SortExec(preserve_partitioning=true)` as the
   input, those properties already claim the sort ordering per partition;
   ProgressiveEval collapsing to one partition turns that into the global
   ordering claim. The claim is justified by our plan-time non-overlap proof —
   the same trust model as the existing `Exact` path for sorted files.
5. Existing upstream machinery that this deliberately does NOT reuse:
   `sort_files_within_groups_by_statistics`, `MinMaxStatistics`
   (`datafusion/datasource/src/file_scan_config/sort_pushdown.rs`,
   `.../statistics.rs`) — all of it requires within-file ordering to reach
   `Exact`, and `MinMaxStatistics` is `pub(crate)` anyway. The batching logic
   must live in delta-rs (Step 2). The NULL-handling guard
   (`any_file_has_nulls_in_sort_columns`) is a good model to copy.

## Target plan shape

Before (today's fallback when files are internally unsorted):

```text
SortPreservingMergeExec(t)                 -- or single global SortExec
  SortExec(t, preserve_partitioning)       -- buffers ALL data before first row
    DeltaScanExec
      DataSourceExec (files bin-packed arbitrarily)
```

After:

```text
SortPreservingMergeExec(t)                 -- passthrough (1 input partition)
  BufferExec                               -- inserted by PushdownSort rule
    ProgressiveEvalExec(t)                 -- 1 output partition, polls inputs in turn
      SortExec(t, preserve_partitioning)   -- sorts ONE batch per partition
        DeltaScanExec
          DataSourceExec (one FileGroup per non-overlapping batch, in range order)
```

## Step 1: Vendor `ProgressiveEvalExec` from PR #10490

Copy `datafusion/physical-plan/src/sorts/progressive_eval.rs` from the PR into
delta-rs (suggested:
`crates/core/src/delta_datafusion/table_provider/next/progressive_eval.rs`).
**Reuse exactly as-is where possible**; the PR is from the DataFusion ~38 era,
so expect only mechanical porting:

- `PlanProperties::new(eq_properties, partitioning, input.execution_mode())`
  → the current 4-arg form with `EmissionType` + `Boundedness`
  (use `EmissionType::Incremental` and the input's boundedness).
- Implement any `ExecutionPlan` trait methods added since (e.g. `name()`);
  check compile errors against the workspace's DataFusion version.
- The PR adds a DataFusion config option
  `progressive_eval_num_prefetch_input_streams` (default 2, i.e. prefetch one
  stream ahead of the one being polled — this is the mitigation for the
  sequential-I/O trade-off). We can't add DataFusion config from delta-rs;
  replace with a constructor parameter / delta-rs table config, defaulting
  to 2.
- Keep the PR's `value_ranges: Option<Vec<(ScalarValue, ScalarValue)>>` field
  and its `DisplayAs` output — populate it from our batch ranges so `EXPLAIN`
  is self-documenting and testable.
- Keep the PR's `fetch: Option<usize>` support and make sure `with_fetch`
  returns a new instance — `PushdownSort` uses it to forward the eliminated
  `SortExec`'s LIMIT, which is what enables early termination.
- Port the PR's unit tests along with the operator.
- Add guard-rail overrides if the PR lacks them:
  `benefits_from_input_partitioning() → vec![false]`,
  `maintains_input_order() → vec![true]`.
- Record the PR commit SHA and any local deviations in a comment header, to
  make a future switch to an upstream version easy.

The critical behavior to preserve when porting: input partitions must be
executed **lazily** (partition *i+1*'s `execute()` not called until stream *i*
is nearly exhausted, modulo prefetch). That laziness is the entire
optimization — with `SortExec` below, `execute()` is what triggers the read
and sort of a batch.

## Step 2: Batch files into non-overlapping range groups (delta-rs)

New plan-time logic (suggested: alongside
`crates/core/src/delta_datafusion/table_provider/next/scan/`), operating on
the per-file min/max stats that the `sort-order` branch already surfaces into
`PartitionedFile::statistics` (see `stats_projection.rs`):

1. Extract (min, max) of the sort column for every file.
2. Sort files by min value; sweep-merge overlapping intervals into batches.
   Batch boundary where `current_batch.max <= next_file.min`. Output: ordered
   list of mutually non-overlapping batches. Touching boundaries
   (`max == min`) are fine under a total order.
3. Rebuild the `FileScanConfig` with **one `FileGroup` per batch, in batch
   order**, `output_ordering` left empty (files are not internally sorted; the
   ordering claim lives on ProgressiveEval instead).

Bail out (fall back to today's `Inexact`/`Unsupported` behavior) when:

- any file lacks min/max stats for the sort column;
- any file has nonzero or *unknown* null count in the sort column (NULLS
  FIRST/LAST placement breaks the concatenation argument — mirror upstream's
  `any_file_has_nulls_in_sort_columns`);
- the sweep collapses everything into one batch (correct but no win — a global
  sort with extra steps);
- the sort key is a string/binary column (v1 restriction): Delta truncates
  string min/max stats, and a truncated max treated as inclusive can make
  batches falsely appear non-overlapping. Timestamps/numerics are exact.
  (Follow-up: widen truncated maxes instead of bailing.)
- retained-row-index contract is active on the scan (it requires
  `Distribution::SinglePartition`; see `DeltaScanExec::required_input_distribution`).

v1 scope: **single-column ASC orderings**. Follow-ups: DESC (same batches,
reversed order — mirror the reverse handling in upstream
`rebuild_with_source`), multi-column lexicographic keys (tuple-wise range
comparison; upstream `MinMaxStatistics` uses the arrow row format for this).

## Step 3: Wire into `DeltaScanExec::try_pushdown_sort`

`crates/core/src/delta_datafusion/table_provider/next/scan/exec.rs:403`
currently maps sort columns to the inner parquet schema and delegates. Add a
fallback arm when delegation does not yield `Exact`:

```rust
match self.input.try_pushdown_sort(&mapped)? {
    Exact { inner } => Exact { inner: self.with_new_input(inner) }, // as today
    Inexact { .. } | Unsupported => {
        let Some((batched_input, ranges)) = self.try_batch_by_ranges(&mapped)? else {
            return /* today's Inexact / Unsupported result */;
        };
        let sort = SortExec::new(order.to_vec().into(), self.with_new_input(batched_input))
            .with_preserve_partitioning(true);
        Exact {
            inner: Arc::new(ProgressiveEvalExec::new(Arc::new(sort), Some(ranges), None)),
        }
    }
}
```

Notes:

- The `SortExec` sits **above `DeltaScanExec`**, sorting on the logical
  schema. This also lifts the current restriction on sort keys that are Delta
  partition columns (materialized above the parquet scan; today they return
  `Unsupported`) — a Hive-style partition value is just a trivially
  non-overlapping range. Worth handling in v1 if cheap, else follow-up.
- Per-batch `fetch`: when `PushdownSort` forwards a LIMIT via `with_fetch`, an
  optional refinement is to also push it into each per-partition `SortExec`
  (TopK per batch). Not required for correctness.
- `DeltaScanExec::execute` asserts its input distribution — make sure the
  composite plan keeps `DeltaScanExec`'s own invariants intact (it becomes a
  child of the new `SortExec`, one instance, unchanged semantics).

## Testing

- Port PR #10490's unit tests with the operator.
- **Laziness test**: mock/counting object store; assert no file from batch 2+
  is opened before the first output batch is emitted, and that under
  `LIMIT n` (n ≤ batch 1 rows) later batches are never opened. (Account for
  the prefetch parameter — set prefetch to 0/1 in the test or assert
  accordingly.)
- **Plan snapshot tests** (extend
  `crates/core/tests/it_datafusion/sort_order.rs`): internally-unsorted,
  range-disjoint files → `EXPLAIN` contains `ProgressiveEvalExec` with
  `input_ranges=...` and no global `SortExec`; overlapping files → global sort
  retained; nulls in sort column → global sort retained.
- **Correctness fuzz**: random datasets with varying overlap patterns
  (disjoint / touching / partial / full overlap, batch counts 1..N); compare
  results against the unoptimized global-sort plan, with and without LIMIT.
- Run `cargo clippy`/`fmt` per repo conventions.

## Benchmarks

Extend `crates/benchmarks/src/sort_order.rs` (see `crates/benchmarks/README.md`):

- time-to-first-batch and total time vs. the global-sort baseline;
- peak memory (largest-batch bound vs. whole-dataset bound);
- `LIMIT` query latency (early termination);
- worst case: fully-overlapping files (should fall back, no regression);
- sensitivity to the prefetch parameter (sequential-I/O trade-off).

## Upstreaming path

The operator is generic; the goal is to eventually delete our copy:

1. Land and prove it in delta-rs (this plan).
2. Bring results + the delta-rs use case to
   <https://github.com/apache/datafusion/issues/15191>, reviving PR #10490's
   implementation.
3. Longer term, propose an upstream pushdown outcome for "non-overlapping
   groups, unsorted within" so `FileScanConfig` itself can plan this for
   `ListingTable`, and delta-rs gets it via delegation the way the `Exact`
   path works today.

## Out of scope

- Writer-side changes (same as `plan.md`).
- Row-group-level range batching (finer than per-file) — possible follow-up.
- Multi-column and string sort keys (see Step 2 restrictions).

## Implementation status (2026-07)

All three steps plus tests and benchmarks are implemented:

- **Step 1** — `crates/core/src/delta_datafusion/table_provider/next/progressive_eval.rs`
  vendors PR #10490 (head `71efd8ff56246f88c77139f5e0d2a62831d602c6`) with its
  unit tests. Deviations (documented in the file header):
  - Ported to the current `ExecutionPlan` trait (4-arg `PlanProperties`,
    `partition_statistics`, `OrderingRequirements`, ...).
  - Prefetch count is a constructor parameter (default 2), not a DataFusion
    config option.
  - The PR's "prefetch ALL streams when fetch is None" behavior is removed —
    with per-batch `SortExec`s below, eager execution of every input partition
    would defeat the memory bound and time-to-first-row entirely.
  - The output stream truncates the record batch that crosses the fetch
    boundary. The PR returned whole "covering" batches (possibly more than
    `fetch` rows), which is only safe with a limit operator above;
    `PushdownSort` removes the TopK `SortExec` and trusts `with_fetch` to
    enforce the limit, so covering-batch semantics returned excess rows.
- **Step 2** — `crates/core/src/delta_datafusion/table_provider/next/scan/range_batching.rs`
  implements the sweep-merge batching with all the planned bail-outs. Extra
  details discovered during implementation:
  - By `PushdownSort` time, `EnforceDistribution` may have (a) split files
    into byte-range parts across partitions — parts are reassembled per file
    (in byte order, within one batch) so per-file deletion-vector masks and
    row order stay correct — or (b) inserted a round-robin `RepartitionExec`
    between `DeltaScanExec` and the `DataSourceExec`; the batching looks
    through those (they only redistribute batches, and the rebuilt scan gets
    its parallelism from one partition per batch).
  - **Idempotence guard**: `PushdownSort`'s `transform_down` descends into the
    replacement subtree and calls `try_pushdown_sort` again on the per-batch
    `SortExec`'s input. Without detecting "already batched exactly like this"
    (compare proposed vs. existing grouping), the fallback re-wraps the plan
    forever — an infinite optimizer loop. This mirrors upstream's
    `any_reordered == false → Unsupported` termination.
  - The rebuilt config sets `preserve_order = true` and empties
    `output_ordering`; group-level statistics are recomputed.
- **Stats availability** — the kernel scan only materializes min/max stats for
  predicate/sort-order columns, and declaring `file_sort_order` would falsely
  assert within-file order. A new provider option
  `TableProviderBuilder::with_stats_columns` (`DeltaScanConfig::stats_columns`)
  materializes per-file min/max + null counts for named columns without
  declaring anything; the optimization stays purely statistics-driven.
- **Step 3** — fallback arm in `DeltaScanExec::try_pushdown_sort`
  (`try_progressive_eval_pushdown` in `scan/exec.rs`), bailing when the
  retained-row-index contract is active. Partition-column sort keys still
  return `Unsupported` (follow-up as planned).
- **Tests** — PR unit tests + sweep unit tests; integration tests in
  `crates/core/tests/it_datafusion/sort_order.rs`: plan snapshots
  (`ProgressiveEvalExec` + `input_ranges=` for unsorted disjoint files; global
  sort retained for overlapping files / nulls / missing stats), LIMIT
  early-termination laziness via the operator's `num_read_inputs` metric
  (2 of 4 batches executed), and a correctness matrix (disjoint / touching /
  partial / contained / full overlap / two batches, with and without LIMIT)
  against the global-sort baseline.
- **Benchmarks** — `sort-gen --shuffle-within-files [--overlap-days N]`
  generates the targeted layout (disjoint ranges, unsorted rows, no
  `sorting_columns` metadata); `sort-bench --modes progressive` uses
  `with_stats_columns` and reports `progressive_eval=` plan shape.
