//! Batch scan files into non-overlapping range groups for ordered reads.
//!
//! This is the planning half of the `ProgressiveEvalExec` optimization (see
//! `progressive_eval.md`): when a query orders by a column on which the
//! table's data files have mutually non-overlapping (or groupable) min/max
//! ranges — but rows *within* each file are not necessarily sorted — the scan
//! can be rebuilt with one file group per non-overlapping range batch. Each
//! batch is then sorted independently and the sorted batches are streamed in
//! turn by `ProgressiveEvalExec`, instead of buffering the whole dataset in a
//! global sort.
//!
//! The analysis is intentionally conservative; whenever the per-file
//! statistics cannot *prove* that concatenating the sorted batches yields the
//! requested ordering, `None` is returned and the caller falls back to the
//! existing behavior (global sort).

use std::sync::Arc;

use arrow_schema::DataType;
use datafusion::common::stats::Precision;
use datafusion::common::{ColumnStatistics, Result, ScalarValue};
use datafusion::physical_expr::expressions::Column;
use datafusion::physical_expr::{Partitioning, PhysicalSortExpr};
use datafusion::physical_plan::ExecutionPlan;
use datafusion::physical_plan::repartition::RepartitionExec;
use datafusion_datasource::PartitionedFile;
use datafusion_datasource::file_groups::FileGroup;
use datafusion_datasource::file_scan_config::FileScanConfig;
use datafusion_datasource::source::DataSourceExec;
use tracing::debug;

use super::MAX_PARTITION_DICT_CARDINALITY;

/// A scan rebuilt with one file group per non-overlapping range batch.
pub(crate) struct RangeBatchedScan {
    /// The rebuilt `DataSourceExec`, with one output partition per batch, in
    /// batch (range) order and no declared output ordering.
    pub input: Arc<dyn ExecutionPlan>,
    /// The (min, max) value range of the sort column covered by each batch,
    /// in batch order.
    pub ranges: Vec<(ScalarValue, ScalarValue)>,
}

/// Try to rebuild `input` (the parquet scan below `DeltaScanExec`) with one
/// file group per non-overlapping batch of the sort column's value ranges.
///
/// `order` must be expressed over `input`'s schema. Returns `Ok(None)` when
/// the optimization does not apply:
///
/// - the ordering is not a single ascending column (v1 restriction: DESC and
///   multi-column lexicographic keys are follow-ups);
/// - the sort key is a string/binary column — Delta truncates string min/max
///   stats, and a truncated max treated as inclusive can make batches falsely
///   appear non-overlapping;
/// - the input is not a single-store `DataSourceExec` over a `FileScanConfig`;
/// - any file lacks min/max stats for the sort column, or has a nonzero or
///   unknown null count in it (NULLS FIRST/LAST placement breaks the
///   concatenation argument);
/// - the sweep collapses everything into a single batch (correct but no win —
///   it would be a global sort with extra steps);
/// - a batch would exceed the file-id dictionary key space.
pub(crate) fn try_batch_scan_by_ranges(
    input: &Arc<dyn ExecutionPlan>,
    order: &[PhysicalSortExpr],
) -> Result<Option<RangeBatchedScan>> {
    // v1 scope: single-column ascending orderings only.
    let [sort_expr] = order else {
        return Ok(None);
    };
    if sort_expr.options.descending {
        return Ok(None);
    }
    let Some(column) = sort_expr.expr.downcast_ref::<Column>() else {
        return Ok(None);
    };

    // Look through round-robin repartitions that `EnforceDistribution` may
    // have inserted below the scan for parallelism: they only redistribute
    // batches, and the rebuilt scan gets its parallelism from one partition
    // per range batch instead.
    let mut input = input;
    while let Some(repartition) = input.downcast_ref::<RepartitionExec>() {
        if !matches!(repartition.partitioning(), Partitioning::RoundRobinBatch(_)) {
            return Ok(None);
        }
        input = repartition.input();
    }

    let Some(source_exec) = input.downcast_ref::<DataSourceExec>() else {
        return Ok(None);
    };
    let Some(config) = source_exec.data_source().downcast_ref::<FileScanConfig>() else {
        return Ok(None);
    };

    // Per-file statistics attached to `PartitionedFile`s are aligned with the
    // table schema (file columns plus partition columns), so resolve the sort
    // column by name there rather than through the scan projection.
    let table_schema = config.file_source.table_schema().table_schema();
    let Ok(stats_index) = table_schema.index_of(column.name()) else {
        return Ok(None);
    };
    if !supports_exact_range_stats(table_schema.field(stats_index).data_type()) {
        return Ok(None);
    }

    // Earlier optimizer passes (`EnforceDistribution`) may have repartitioned
    // the scan, splitting files into byte-range parts spread across
    // partitions. Reassemble the parts by file path so each file is batched
    // exactly once and all of its parts stay adjacent, in byte order, within
    // one batch: deletion-vector masks and row order are per file and require
    // one stream to see a file's rows from the start.
    let mut part_index_by_path: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    let mut files: Vec<(Vec<&PartitionedFile>, &str)> = Vec::new();
    for file in config.file_groups.iter().flat_map(|g| g.iter()) {
        let path = file.object_meta.location.as_ref();
        match part_index_by_path.get(path) {
            Some(&index) => files[index].0.push(file),
            None => {
                part_index_by_path.insert(path, files.len());
                files.push((vec![file], path));
            }
        }
    }
    for (parts, _) in files.iter_mut() {
        parts.sort_by_key(|part| part.range.as_ref().map(|r| r.start));
    }
    if files.len() < 2 {
        return Ok(None);
    }

    let mut file_ranges = Vec::with_capacity(files.len());
    for (parts, _) in &files {
        let Some(range) = file_sort_column_range(parts[0], stats_index) else {
            return Ok(None);
        };
        file_ranges.push(range);
    }

    let Some(batches) = sweep_into_batches(&file_ranges) else {
        return Ok(None);
    };
    if batches.len() < 2 {
        // A single batch is correct but is just a global sort with extra
        // steps; let the regular sort handle it.
        return Ok(None);
    }
    if batches.iter().any(|b| {
        b.iter().map(|&i| files[i].0.len()).sum::<usize>() > MAX_PARTITION_DICT_CARDINALITY
    }) {
        debug!(
            "range batching would exceed the file-id dictionary key space in one batch; falling back"
        );
        return Ok(None);
    }

    let mut file_groups = Vec::with_capacity(batches.len());
    let mut ranges = Vec::with_capacity(batches.len());
    for batch in &batches {
        file_groups.push(
            batch
                .iter()
                .flat_map(|&file_index| files[file_index].0.iter().map(|&part| part.clone()))
                .collect::<FileGroup>(),
        );
        let (batch_min, _) = file_ranges[batch[0]].clone();
        let batch_max = batch
            .iter()
            .map(|&file_index| file_ranges[file_index].1.clone())
            .try_fold(None::<ScalarValue>, |acc, max| match acc {
                None => Some(Some(max)),
                Some(acc) => Some(Some(match acc.partial_cmp(&max)? {
                    std::cmp::Ordering::Less => max,
                    _ => acc,
                })),
            })
            .flatten();
        // The sweep already compared every value; a failure here is unreachable.
        let Some(batch_max) = batch_max else {
            return Ok(None);
        };
        ranges.push((batch_min, batch_max));
    }

    // Idempotence guard: if the scan already has exactly this grouping, it has
    // already been range-batched (this pushdown runs inside `PushdownSort`'s
    // `transform_down`, which descends into the per-batch `SortExec` the
    // caller inserts and asks again). Rebuilding an identical plan here would
    // wrap sort-over-scan endlessly. Mirrors upstream's `any_reordered ==
    // false → Unsupported` termination in `try_sort_file_groups_by_statistics`.
    if same_grouping(&config.file_groups, &file_groups) {
        return Ok(None);
    }

    let mut new_config = config.clone();
    new_config.file_groups = file_groups;
    // The files are not internally sorted: the ordering claim lives on the
    // ProgressiveEvalExec the caller puts on top, not on the scan.
    new_config.output_ordering = vec![];
    // Batches must be executed in range order for the concatenation to be
    // ordered; forbid any file reordering below us.
    new_config.preserve_order = true;

    Ok(Some(RangeBatchedScan {
        input: DataSourceExec::from_data_source(new_config),
        ranges,
    }))
}

/// Whether two file groupings list the same file parts in the same order.
fn same_grouping(a: &[FileGroup], b: &[FileGroup]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(group_a, group_b)| {
            group_a.len() == group_b.len()
                && group_a.iter().zip(group_b.iter()).all(|(file_a, file_b)| {
                    file_a.object_meta.location == file_b.object_meta.location
                        && file_a.range == file_b.range
                })
        })
}

/// Whether Delta min/max statistics for this type are exact.
///
/// String and binary min/max values may be truncated in Delta file statistics,
/// and a truncated max treated as inclusive can make ranges falsely appear
/// non-overlapping, so they must not drive range batching.
fn supports_exact_range_stats(data_type: &DataType) -> bool {
    data_type.is_numeric()
        || matches!(
            data_type,
            DataType::Boolean
                | DataType::Date32
                | DataType::Date64
                | DataType::Time32(_)
                | DataType::Time64(_)
                | DataType::Timestamp(_, _)
                | DataType::Duration(_)
        )
}

/// Extract the (min, max) range of the sort column for one file, requiring a
/// provably null-free file: known min/max values and an exact zero null count.
fn file_sort_column_range(
    file: &PartitionedFile,
    stats_index: usize,
) -> Option<(ScalarValue, ScalarValue)> {
    let stats = file.statistics.as_ref()?;
    let column_stats: &ColumnStatistics = stats.column_statistics.get(stats_index)?;

    // Mirror upstream `any_file_has_nulls_in_sort_columns`: an unknown null
    // count must be assumed to be nonzero.
    match column_stats.null_count {
        Precision::Exact(0) => {}
        _ => return None,
    }

    // `Inexact` min/max are estimates and cannot prove non-overlap.
    let (Precision::Exact(min), Precision::Exact(max)) =
        (&column_stats.min_value, &column_stats.max_value)
    else {
        return None;
    };
    if min.is_null() || max.is_null() {
        return None;
    }
    Some((min.clone(), max.clone()))
}

/// Sweep-merge per-file (min, max) ranges into ordered, mutually
/// non-overlapping batches.
///
/// Returns the file indices of each batch, with batches in ascending range
/// order, such that `batch[i].max <= batch[i+1].min` for all consecutive
/// batches. Touching boundaries (`max == min`) are fine for a single-column
/// ascending ordering: equal keys are interchangeable under that order.
///
/// Returns `None` when any pair of values is incomparable (mixed or unordered
/// types), which callers must treat as "cannot prove non-overlap".
fn sweep_into_batches(ranges: &[(ScalarValue, ScalarValue)]) -> Option<Vec<Vec<usize>>> {
    use std::cmp::Ordering;

    let mut order: Vec<usize> = (0..ranges.len()).collect();
    let mut comparable = true;
    order.sort_by(|&a, &b| {
        let (a_min, a_max) = &ranges[a];
        let (b_min, b_max) = &ranges[b];
        match a_min.partial_cmp(b_min) {
            Some(Ordering::Equal) => a_max.partial_cmp(b_max).unwrap_or_else(|| {
                comparable = false;
                Ordering::Equal
            }),
            Some(ordering) => ordering,
            None => {
                comparable = false;
                Ordering::Equal
            }
        }
    });
    if !comparable {
        return None;
    }

    let mut batches: Vec<Vec<usize>> = Vec::new();
    let mut current_max: Option<ScalarValue> = None;
    for file_index in order {
        let (min, max) = &ranges[file_index];
        // `current_max <= min` closes the current batch; otherwise the file
        // overlaps it and joins it.
        let starts_new_batch = match &current_max {
            None => true,
            Some(batch_max) => batch_max.partial_cmp(min)? != Ordering::Greater,
        };
        if starts_new_batch {
            batches.push(vec![file_index]);
            current_max = Some(max.clone());
        } else {
            batches.last_mut().expect("batch exists").push(file_index);
            let batch_max = current_max.as_ref().expect("current_max exists");
            if batch_max.partial_cmp(max)? == Ordering::Less {
                current_max = Some(max.clone());
            }
        }
    }

    Some(batches)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int_ranges(ranges: &[(i64, i64)]) -> Vec<(ScalarValue, ScalarValue)> {
        ranges
            .iter()
            .map(|(min, max)| {
                (
                    ScalarValue::Int64(Some(*min)),
                    ScalarValue::Int64(Some(*max)),
                )
            })
            .collect()
    }

    #[test]
    fn test_sweep_disjoint_files() {
        // Already disjoint, listed out of order.
        let batches = sweep_into_batches(&int_ranges(&[(20, 29), (0, 9), (10, 19)])).unwrap();
        assert_eq!(batches, vec![vec![1], vec![2], vec![0]]);
    }

    #[test]
    fn test_sweep_touching_boundaries() {
        // max == next min stays a batch boundary under a total order.
        let batches = sweep_into_batches(&int_ranges(&[(0, 10), (10, 20)])).unwrap();
        assert_eq!(batches, vec![vec![0], vec![1]]);
    }

    #[test]
    fn test_sweep_partial_overlap_merges() {
        let batches =
            sweep_into_batches(&int_ranges(&[(0, 15), (10, 19), (30, 40), (25, 32)])).unwrap();
        assert_eq!(batches, vec![vec![0, 1], vec![3, 2]]);
    }

    #[test]
    fn test_sweep_containment_extends_batch() {
        // File 1 is contained in file 0's range; file 2 overlaps file 0's max
        // even though it doesn't overlap file 1.
        let batches = sweep_into_batches(&int_ranges(&[(0, 50), (5, 10), (20, 60)])).unwrap();
        assert_eq!(batches, vec![vec![0, 1, 2]]);
    }

    #[test]
    fn test_sweep_full_overlap_single_batch() {
        let batches = sweep_into_batches(&int_ranges(&[(0, 100), (10, 90), (20, 80)])).unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 3);
    }

    #[test]
    fn test_sweep_incomparable_types_bails() {
        let ranges = vec![
            (ScalarValue::Int64(Some(0)), ScalarValue::Int64(Some(10))),
            (
                ScalarValue::Utf8(Some("a".into())),
                ScalarValue::Utf8(Some("b".into())),
            ),
        ];
        assert!(sweep_into_batches(&ranges).is_none());
    }

    #[test]
    fn test_sweep_equal_ranges() {
        // Identical ranges overlap (min < max) and must share a batch.
        let batches = sweep_into_batches(&int_ranges(&[(0, 10), (0, 10)])).unwrap();
        assert_eq!(batches.len(), 1);
        // Point ranges at the same value touch and may split.
        let batches = sweep_into_batches(&int_ranges(&[(5, 5), (5, 5)])).unwrap();
        assert_eq!(batches.len(), 2);
    }

    #[test]
    fn test_supported_range_types() {
        use arrow_schema::TimeUnit;
        assert!(supports_exact_range_stats(&DataType::Int64));
        assert!(supports_exact_range_stats(&DataType::Timestamp(
            TimeUnit::Microsecond,
            None
        )));
        assert!(supports_exact_range_stats(&DataType::Date32));
        assert!(supports_exact_range_stats(&DataType::Float64));
        assert!(!supports_exact_range_stats(&DataType::Utf8));
        assert!(!supports_exact_range_stats(&DataType::Utf8View));
        assert!(!supports_exact_range_stats(&DataType::Binary));
        assert!(!supports_exact_range_stats(&DataType::BinaryView));
    }
}
