//! Sort-order pushdown for [`DeltaScanExec`](super::exec::DeltaScanExec).
//!
//! DataFusion's `PushdownSort` physical optimizer rule calls
//! [`ExecutionPlan::try_pushdown_sort`] on the input of a `SortExec`. When a
//! Delta table declares a per-file sort order (`DeltaScanConfig::file_sort_order`)
//! *and* the query orders by `[<partition columns…>, <file sort order prefix…>]`,
//! the scan can satisfy that ordering without a `SortExec`:
//!
//! * Every data file belongs to exactly one partition, so within a file every
//!   partition column is constant. A file sorted by the declared file sort order
//!   is therefore also sorted by `[<any partition columns…>, <file sort order…>]`.
//! * Partition-column values are known exactly per file, so files can be
//!   bucketed by partition-column tuple, ordered within each bucket on the file
//!   sort order (reusing DataFusion's statistics-based non-overlap check), and
//!   the buckets concatenated in partition-column order.
//!
//! The resulting file groups are mutually non-overlapping and range-ordered on
//! the combined ordering, so [`DeltaScanExec`](super::exec::DeltaScanExec)
//! advertises it as an output ordering; the `SortExec` is removed and the
//! `SortPreservingMergeExec` above it is later rewritten to a
//! `ProgressiveEvalExec` by [`ProgressiveEvalRule`](super::super::ProgressiveEvalRule).
//!
//! This module holds the pure planning algorithm; the `ExecutionPlan` wiring and
//! plan (de)construction live in [`super::exec`].

use std::cmp::Ordering;
use std::sync::Arc;

use arrow_schema::{SchemaRef, SortOptions};
use datafusion::common::{ColumnStatistics, HashMap, Result, stats::Precision};
use datafusion::physical_expr::expressions::Column;
use datafusion::physical_expr::{LexOrdering, PhysicalSortExpr};
use datafusion::scalar::ScalarValue;
use datafusion_datasource::file_groups::FileGroup;
use datafusion_datasource::{PartitionedFile, file_scan_config::FileScanConfig};

use super::{MAX_PARTITION_DICT_CARDINALITY, chunk_ordered_files};

/// Outcome of planning a sort pushdown: the regrouped, range-ordered file groups
/// plus the per-execution-partition partition-column statistics that
/// [`DeltaScanExec`](super::exec::DeltaScanExec) needs to expose so downstream
/// rules can prove the partitions non-overlapping.
pub(super) struct SortPushdownPlan {
    /// File groups, mutually non-overlapping and range-ordered on the combined
    /// `[partition prefix…, file sort order prefix…]` ordering.
    pub(super) file_groups: Vec<FileGroup>,
    /// Per-group exact statistics for the leading partition columns of the
    /// requested ordering, keyed by logical column name. Aligned with
    /// `file_groups` by index.
    pub(super) per_partition_stats: Vec<HashMap<String, ColumnStatistics>>,
}

/// A partition-column sort key extracted from the requested ordering.
struct PrefixColumn {
    /// Logical (output-schema) column name.
    name: String,
    options: SortOptions,
}

/// A file paired with its exact leading-partition-column values (aligned with
/// the requested ordering's partition prefix).
struct FileEntry {
    file: PartitionedFile,
    prefix_values: Vec<ScalarValue>,
}

/// Recover the source file URL that [`super::get_data_scan_plan`] stashed as the
/// synthetic file-id partition value on each [`PartitionedFile`].
fn file_url_of(file: &PartitionedFile) -> Option<String> {
    match file.partition_values.first()? {
        ScalarValue::Dictionary(_, inner) => match inner.as_ref() {
            ScalarValue::Utf8(Some(s))
            | ScalarValue::LargeUtf8(Some(s))
            | ScalarValue::Utf8View(Some(s)) => Some(s.clone()),
            _ => None,
        },
        ScalarValue::Utf8(Some(s)) => Some(s.clone()),
        _ => None,
    }
}

/// Compare two partition-prefix value tuples under the prefix column options.
///
/// Returns `None` when a pair of values is incomparable (e.g. mismatched
/// [`ScalarValue`] variants), so callers can reject the pushdown rather than
/// silently treat them as equal.
fn cmp_prefix(a: &[ScalarValue], b: &[ScalarValue], prefix: &[PrefixColumn]) -> Option<Ordering> {
    for ((lhs, rhs), col) in a.iter().zip(b.iter()).zip(prefix.iter()) {
        let ord = lhs.partial_cmp(rhs)?;
        let ord = if col.options.descending {
            ord.reverse()
        } else {
            ord
        };
        if ord != Ordering::Equal {
            return Some(ord);
        }
    }
    Some(Ordering::Equal)
}

/// Plan a sort pushdown for the requested `order`, or return `None` when it
/// cannot be satisfied exactly (the caller then reports `Unsupported`).
///
/// * `output_schema` – the scan's logical output schema (`order` is bound to it).
/// * `parquet_read_schema` – physical file columns (`file_sort_order` is bound to
///   it); also the prefix of the file scan's table schema, so column indices
///   match `PartitionedFile` statistics.
/// * `partition_column_names` – logical partition columns, in table order.
/// * `file_sort_order` – resolved per-file ordering over `parquet_read_schema`.
/// * `partition_values_by_file` – exact partition-column values per file URL,
///   aligned with `partition_column_names`.
/// * `files` – the flattened file list from the inner file scan.
/// * `target_groups` – desired execution-partition count (the inner scan's
///   current partition count).
#[allow(clippy::too_many_arguments)]
pub(super) fn plan_sort_pushdown(
    order: &[PhysicalSortExpr],
    output_schema: &SchemaRef,
    parquet_read_schema: &SchemaRef,
    partition_column_names: &[String],
    file_sort_order: Option<&LexOrdering>,
    partition_values_by_file: &HashMap<String, Vec<ScalarValue>>,
    parquet_table_schema: &SchemaRef,
    files: Vec<PartitionedFile>,
    target_groups: usize,
) -> Result<Option<SortPushdownPlan>> {
    if order.is_empty() || files.is_empty() || partition_column_names.is_empty() {
        return Ok(None);
    }

    let column_name = |schema: &SchemaRef, sort_expr: &PhysicalSortExpr| -> Option<String> {
        let col = sort_expr.expr.downcast_ref::<Column>()?;
        let field = schema.fields().get(col.index())?;
        Some(field.name().clone())
    };

    // --- Split the requested ordering into a partition-column prefix and a
    // data-column suffix. ---
    let mut prefix_len = 0;
    for sort_expr in order {
        let Some(name) = column_name(output_schema, sort_expr) else {
            return Ok(None);
        };
        if partition_column_names.contains(&name) {
            prefix_len += 1;
        } else {
            break;
        }
    }
    if prefix_len == 0 {
        // No partition prefix: the plain per-file path (handled at scan planning
        // time) already covers this; nothing to add here.
        return Ok(None);
    }
    let (prefix_exprs, suffix_exprs) = order.split_at(prefix_len);

    let prefix: Vec<PrefixColumn> = prefix_exprs
        .iter()
        .map(|sort_expr| PrefixColumn {
            name: column_name(output_schema, sort_expr).expect("checked above"),
            options: sort_expr.options,
        })
        .collect();

    // The suffix must reference only data columns and match a prefix of the
    // declared file sort order (same columns, same direction).
    let mut suffix_indices: Vec<usize> = Vec::with_capacity(suffix_exprs.len());
    if !suffix_exprs.is_empty() {
        let Some(file_sort_order) = file_sort_order else {
            return Ok(None);
        };
        if suffix_exprs.len() > file_sort_order.len() {
            return Ok(None);
        }
        for (suffix_expr, file_sort_expr) in suffix_exprs.iter().zip(file_sort_order.iter()) {
            let Some(suffix_name) = column_name(output_schema, suffix_expr) else {
                return Ok(None);
            };
            if partition_column_names.contains(&suffix_name) {
                // A partition column after the prefix cannot be honored by
                // regrouping: the data files are not ordered on it.
                return Ok(None);
            }
            let Some(file_sort_col) = file_sort_expr.expr.downcast_ref::<Column>() else {
                return Ok(None);
            };
            let Some(file_sort_name) = parquet_read_schema
                .fields()
                .get(file_sort_col.index())
                .map(|f| f.name())
            else {
                return Ok(None);
            };
            if *file_sort_name != suffix_name || suffix_expr.options != file_sort_expr.options {
                return Ok(None);
            }
            suffix_indices.push(file_sort_col.index());
        }
    }

    // --- Pair every file with its exact leading-partition-column values. ---
    let prefix_positions: Vec<usize> = prefix
        .iter()
        .map(|col| {
            partition_column_names
                .iter()
                .position(|name| *name == col.name)
                .expect("prefix column is a partition column")
        })
        .collect();

    let mut entries: Vec<FileEntry> = Vec::with_capacity(files.len());
    for file in files {
        let Some(url) = file_url_of(&file) else {
            return Ok(None);
        };
        let Some(values) = partition_values_by_file.get(&url) else {
            return Ok(None);
        };
        let mut prefix_values = Vec::with_capacity(prefix_positions.len());
        for &pos in &prefix_positions {
            match values.get(pos) {
                Some(value) if !value.is_null() => prefix_values.push(value.clone()),
                // A null partition value cannot be ordered against non-null
                // values via min/max statistics; bail rather than risk a wrong
                // ordering claim.
                _ => return Ok(None),
            }
        }
        entries.push(FileEntry {
            file,
            prefix_values,
        });
    }

    // --- Bucket files by partition-prefix tuple, ordered by the prefix. ---
    // The sort is best-effort: it needs a total order, so incomparable values
    // fall back to `Equal` and may land anywhere. The strict boundary check
    // below is what makes the resulting bucket order sound.
    entries.sort_by(|a, b| {
        cmp_prefix(&a.prefix_values, &b.prefix_values, &prefix).unwrap_or(Ordering::Equal)
    });

    let mut buckets: Vec<(Vec<ScalarValue>, Vec<PartitionedFile>)> = Vec::new();
    for entry in entries {
        match buckets.last_mut() {
            Some((key, files)) if *key == entry.prefix_values => files.push(entry.file),
            _ => buckets.push((entry.prefix_values, vec![entry.file])),
        }
    }

    // Every bucket must be strictly ordered against its predecessor: the groups
    // are concatenated in this order and the scan advertises the result as an
    // output ordering. Bucket boundaries are cut on `PartialEq` while the sort
    // above uses `cmp_prefix`, so the two can disagree — an incomparable pair,
    // or one that compares equal without being equal, must reject the pushdown
    // rather than emit an out-of-order concatenation.
    if !buckets
        .windows(2)
        .all(|pair| cmp_prefix(&pair[0].0, &pair[1].0, &prefix) == Some(Ordering::Less))
    {
        return Ok(None);
    }

    // Guard against pathological partition cardinality producing an unbounded
    // number of scan partitions.
    let max_buckets = usize::max(64, target_groups.saturating_mul(2));
    if buckets.len() > max_buckets {
        return Ok(None);
    }

    // --- Order each bucket on the suffix and verify mutual non-overlap. ---
    let suffix_ordering = if suffix_exprs.is_empty() {
        None
    } else {
        let exprs: Vec<_> = suffix_exprs
            .iter()
            .zip(&suffix_indices)
            .map(|(sort_expr, &index)| {
                let name = parquet_read_schema.field(index).name();
                PhysicalSortExpr::new(Arc::new(Column::new(name, index)), sort_expr.options)
            })
            .collect();
        match LexOrdering::new(exprs) {
            Some(ordering) => Some(ordering),
            // Non-empty by construction; bail rather than silently claim an
            // ordering we did not enforce.
            None => return Ok(None),
        }
    };

    let mut ordered_buckets: Vec<Vec<PartitionedFile>> = Vec::with_capacity(buckets.len());
    for (_, bucket) in buckets {
        let Some(suffix_ordering) = suffix_ordering.as_ref().filter(|_| bucket.len() > 1) else {
            ordered_buckets.push(bucket);
            continue;
        };

        // Concatenating multiple files into one group interleaves each file's
        // nulls into the middle of the group; min/max cannot detect that, so a
        // suffix column that may be null disqualifies a multi-file bucket.
        for file in &bucket {
            for &index in &suffix_indices {
                let non_nullable = !parquet_read_schema.field(index).is_nullable();
                let null_free = file
                    .statistics
                    .as_ref()
                    .and_then(|stats| stats.column_statistics.get(index))
                    .is_some_and(|col| col.null_count == Precision::Exact(0));
                if !non_nullable && !null_free {
                    return Ok(None);
                }
            }
        }

        let flat = vec![FileGroup::new(bucket)];
        match FileScanConfig::split_groups_by_statistics(
            parquet_table_schema,
            &flat,
            suffix_ordering,
        ) {
            // Exactly one group back means the bucket's files are mutually
            // non-overlapping on the suffix and now correctly ordered.
            Ok(mut groups) if groups.len() == 1 => {
                ordered_buckets.push(groups.remove(0).into_inner());
            }
            // Overlapping files within one partition value: not handled here.
            _ => return Ok(None),
        }
    }

    // --- Split buckets into contiguous groups without ever spanning a bucket
    // boundary, so every group boundary is either suffix-ordered (within a
    // bucket) or a strict partition-column step (between buckets). ---
    let file_groups = chunk_buckets(&ordered_buckets, target_groups);
    if file_groups
        .iter()
        .any(|group| group.len() > MAX_PARTITION_DICT_CARDINALITY)
    {
        return Ok(None);
    }

    // --- Per-group exact statistics for the prefix partition columns. ---
    let mut per_partition_stats: Vec<HashMap<String, ColumnStatistics>> =
        Vec::with_capacity(file_groups.len());
    for group in &file_groups {
        let mut group_stats: HashMap<String, ColumnStatistics> = HashMap::new();
        for (col, &pos) in prefix.iter().zip(&prefix_positions) {
            let mut min_value: Option<ScalarValue> = None;
            let mut max_value: Option<ScalarValue> = None;
            for file in group.iter() {
                let url = file_url_of(file).expect("validated above");
                let value = partition_values_by_file
                    .get(&url)
                    .and_then(|values| values.get(pos))
                    .cloned()
                    .expect("validated above");
                min_value = Some(match min_value {
                    Some(current) if current.partial_cmp(&value) == Some(Ordering::Less) => current,
                    _ => value.clone(),
                });
                max_value = Some(match max_value {
                    Some(current) if current.partial_cmp(&value) == Some(Ordering::Greater) => {
                        current
                    }
                    _ => value,
                });
            }
            group_stats.insert(
                col.name.clone(),
                ColumnStatistics {
                    null_count: Precision::Exact(0),
                    min_value: Precision::Exact(min_value.expect("group is non-empty")),
                    max_value: Precision::Exact(max_value.expect("group is non-empty")),
                    distinct_count: Precision::Absent,
                    sum_value: Precision::Absent,
                    byte_size: Precision::Absent,
                },
            );
        }
        per_partition_stats.push(group_stats);
    }

    Ok(Some(SortPushdownPlan {
        file_groups,
        per_partition_stats,
    }))
}

/// Split each bucket's ordered file list into contiguous groups, allocating the
/// `target` group budget across buckets in proportion to their file counts. A
/// group never spans two buckets.
fn chunk_buckets(buckets: &[Vec<PartitionedFile>], target: usize) -> Vec<FileGroup> {
    let total_files: usize = buckets.iter().map(|bucket| bucket.len()).sum();
    if total_files == 0 {
        return Vec::new();
    }
    let mut remaining_target = target.max(1);
    let mut remaining_files = total_files;
    let mut out = Vec::new();
    for bucket in buckets {
        let bucket_files = bucket.len();
        // Ceil-divide the remaining budget by remaining files, then scale by
        // this bucket, so small buckets still get at least one group and the
        // budget is not exhausted early.
        let want = remaining_target
            .saturating_mul(bucket_files)
            .div_ceil(remaining_files.max(1));
        let groups = want.clamp(1, bucket_files);
        out.extend(chunk_ordered_files(bucket.clone(), groups));
        remaining_target = remaining_target.saturating_sub(groups).max(1);
        remaining_files -= bucket_files;
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow_array::{ArrayRef, RecordBatch};
    use arrow_schema::{DataType, Field, Schema};
    use datafusion::common::Statistics;

    use super::*;
    use crate::delta_datafusion::file_id::wrap_file_id_value;

    fn asc(index: usize, name: &str) -> PhysicalSortExpr {
        PhysicalSortExpr::new(
            Arc::new(Column::new(name, index)),
            SortOptions {
                descending: false,
                nulls_first: false,
            },
        )
    }

    fn output_schema() -> SchemaRef {
        Arc::new(Schema::new(vec![
            Field::new("part", DataType::Utf8, false),
            Field::new("timestamp", DataType::Int64, false),
            Field::new("value", DataType::Int64, false),
        ]))
    }

    fn parquet_read_schema() -> SchemaRef {
        Arc::new(Schema::new(vec![
            // Nullable so multi-file groups exercise the null-freeness check.
            Field::new("timestamp", DataType::Int64, true),
            Field::new("value", DataType::Int64, true),
        ]))
    }

    fn parquet_table_schema() -> SchemaRef {
        Arc::new(Schema::new(vec![
            Field::new("timestamp", DataType::Int64, true),
            Field::new("value", DataType::Int64, true),
            Field::new("__delta_rs_file_id__", DataType::Utf8, false),
        ]))
    }

    fn file_sort_order() -> LexOrdering {
        LexOrdering::new(vec![asc(0, "timestamp")]).unwrap()
    }

    /// A file carrying its synthetic file-id partition value and exact
    /// timestamp min/max statistics (index 0 of the parquet table schema).
    fn file(url: &str, ts_min: i64, ts_max: i64, ts_nulls: usize) -> PartitionedFile {
        let mut file = PartitionedFile::new(url.to_string(), 100);
        file.partition_values = vec![wrap_file_id_value(url)];
        file.statistics = Some(Arc::new(Statistics {
            num_rows: Precision::Exact(10),
            total_byte_size: Precision::Exact(100),
            column_statistics: vec![
                ColumnStatistics {
                    null_count: Precision::Exact(ts_nulls),
                    min_value: Precision::Exact(ScalarValue::Int64(Some(ts_min))),
                    max_value: Precision::Exact(ScalarValue::Int64(Some(ts_max))),
                    ..Default::default()
                },
                ColumnStatistics::default(),
                ColumnStatistics::default(),
            ],
        }));
        file
    }

    fn values(part: &str) -> Vec<ScalarValue> {
        vec![ScalarValue::Utf8(Some(part.to_string()))]
    }

    struct Fixture {
        files: Vec<PartitionedFile>,
        partition_values_by_file: HashMap<String, Vec<ScalarValue>>,
    }

    impl Fixture {
        /// `specs` is `(url, part, ts_min, ts_max)`.
        fn new(specs: &[(&str, &str, i64, i64)]) -> Self {
            let mut files = Vec::new();
            let mut partition_values_by_file = HashMap::new();
            for (url, part, ts_min, ts_max) in specs {
                files.push(file(url, *ts_min, *ts_max, 0));
                partition_values_by_file.insert((*url).to_string(), values(part));
            }
            Self {
                files,
                partition_values_by_file,
            }
        }

        fn plan(
            &self,
            order: &[PhysicalSortExpr],
            file_sort_order: Option<&LexOrdering>,
            target_groups: usize,
        ) -> Option<SortPushdownPlan> {
            plan_sort_pushdown(
                order,
                &output_schema(),
                &parquet_read_schema(),
                &["part".to_string()],
                file_sort_order,
                &self.partition_values_by_file,
                &parquet_table_schema(),
                self.files.clone(),
                target_groups,
            )
            .unwrap()
        }
    }

    fn group_urls(group: &FileGroup) -> Vec<String> {
        group
            .iter()
            .map(|f| f.object_meta.location.to_string())
            .collect()
    }

    #[test]
    fn non_overlapping_within_partition_forms_one_group_per_file() {
        let fixture = Fixture::new(&[
            ("a2", "A", 200, 299),
            ("a0", "A", 0, 99),
            ("b0", "B", 50, 149),
            ("a1", "A", 100, 199),
        ]);
        let order = vec![asc(0, "part"), asc(1, "timestamp")];

        let plan = fixture
            .plan(&order, Some(&file_sort_order()), 4)
            .expect("expected a pushdown plan");

        assert_eq!(plan.file_groups.len(), 4);
        let flat: Vec<_> = plan.file_groups.iter().flat_map(group_urls).collect();
        assert_eq!(flat, vec!["a0", "a1", "a2", "b0"]);

        // Every group is single-partition and its `part` stats are exact.
        for (idx, expected) in ["A", "A", "A", "B"].iter().enumerate() {
            let stat = &plan.per_partition_stats[idx]["part"];
            assert_eq!(stat.null_count, Precision::Exact(0));
            assert_eq!(
                stat.min_value,
                Precision::Exact(ScalarValue::Utf8(Some((*expected).to_string())))
            );
            assert_eq!(stat.min_value, stat.max_value);
        }
    }

    #[test]
    fn groups_never_span_a_partition_boundary() {
        let fixture = Fixture::new(&[
            ("a0", "A", 0, 99),
            ("a1", "A", 100, 199),
            ("a2", "A", 200, 299),
            ("b0", "B", 50, 149),
        ]);
        let order = vec![asc(0, "part"), asc(1, "timestamp")];

        // Fewer target groups than files: buckets are split but a group must
        // still not mix partition values.
        let plan = fixture
            .plan(&order, Some(&file_sort_order()), 2)
            .expect("expected a pushdown plan");

        for group in &plan.file_groups {
            let parts: std::collections::HashSet<_> = group
                .iter()
                .map(|f| {
                    let url = f.object_meta.location.to_string();
                    fixture.partition_values_by_file[&url][0].clone()
                })
                .collect();
            assert_eq!(parts.len(), 1, "a group spans two partition values");
        }
    }

    #[test]
    fn overlapping_files_within_a_partition_are_not_supported() {
        let fixture = Fixture::new(&[
            ("a0", "A", 0, 150),
            ("a1", "A", 100, 199),
            ("b0", "B", 0, 99),
        ]);
        let order = vec![asc(0, "part"), asc(1, "timestamp")];

        assert!(fixture.plan(&order, Some(&file_sort_order()), 4).is_none());
    }

    #[test]
    fn incomparable_partition_values_are_not_supported() {
        // Mismatched `ScalarValue` variants for one partition column are
        // incomparable. The best-effort sort cannot order them, and bucket
        // boundaries are cut on `PartialEq`, so without the strict boundary
        // check the buckets would be concatenated in an arbitrary order while
        // the scan advertises `[part, timestamp]` as an output ordering.
        let files = vec![file("a0", 0, 99, 0), file("b0", 100, 199, 0)];
        let mut partition_values_by_file = HashMap::new();
        partition_values_by_file.insert("a0".to_string(), values("A"));
        partition_values_by_file.insert("b0".to_string(), vec![ScalarValue::Int64(Some(1))]);
        let order = vec![asc(0, "part"), asc(1, "timestamp")];

        let plan = plan_sort_pushdown(
            &order,
            &output_schema(),
            &parquet_read_schema(),
            &["part".to_string()],
            Some(&file_sort_order()),
            &partition_values_by_file,
            &parquet_table_schema(),
            files,
            4,
        )
        .unwrap();

        assert!(plan.is_none());
    }

    #[test]
    fn nulls_in_a_multi_file_bucket_suffix_are_not_supported() {
        let mut fixture = Fixture::new(&[("a0", "A", 0, 99), ("a1", "A", 100, 199)]);
        // Give the second file a nullable-looking timestamp column with nulls.
        fixture.files[1] = file("a1", 100, 199, 3);
        let order = vec![asc(0, "part"), asc(1, "timestamp")];

        assert!(fixture.plan(&order, Some(&file_sort_order()), 4).is_none());
    }

    #[test]
    fn leading_data_column_is_not_supported() {
        let fixture = Fixture::new(&[("a0", "A", 0, 99), ("b0", "B", 0, 99)]);
        let order = vec![asc(1, "timestamp"), asc(0, "part")];

        assert!(fixture.plan(&order, Some(&file_sort_order()), 4).is_none());
    }

    #[test]
    fn suffix_must_match_the_declared_file_sort_order() {
        let fixture = Fixture::new(&[("a0", "A", 0, 99), ("b0", "B", 0, 99)]);
        // `value` is not the declared file sort column.
        let order = vec![asc(0, "part"), asc(2, "value")];

        assert!(fixture.plan(&order, Some(&file_sort_order()), 4).is_none());
    }

    #[test]
    fn partition_only_ordering_needs_no_file_sort_order() {
        let fixture = Fixture::new(&[("b1", "B", 0, 99), ("a0", "A", 0, 99), ("b0", "B", 0, 99)]);
        let order = vec![asc(0, "part")];

        let plan = fixture
            .plan(&order, None, 4)
            .expect("partition-only ordering should be satisfiable");

        let flat: Vec<_> = plan.file_groups.iter().flat_map(group_urls).collect();
        assert_eq!(flat[0], "a0");
        assert!(flat[1..].iter().all(|url| url.starts_with('b')));
    }

    #[test]
    fn descending_partition_prefix_orders_buckets_in_reverse() {
        let fixture = Fixture::new(&[("a0", "A", 0, 99), ("b0", "B", 0, 99)]);
        let order = vec![
            PhysicalSortExpr::new(
                Arc::new(Column::new("part", 0)),
                SortOptions {
                    descending: true,
                    nulls_first: true,
                },
            ),
            asc(1, "timestamp"),
        ];

        let plan = fixture
            .plan(&order, Some(&file_sort_order()), 4)
            .expect("expected a pushdown plan");
        let flat: Vec<_> = plan.file_groups.iter().flat_map(group_urls).collect();
        assert_eq!(flat, vec!["b0", "a0"]);
    }

    /// One record batch per (partition, day range), each sorted by timestamp.
    /// Timestamp ranges never overlap within a partition but do across
    /// partitions, so `ORDER BY part, timestamp` can only be answered without a
    /// `SortExec` by regrouping the files per partition value.
    fn write_batch(part: &str, start: i64, len: i64) -> RecordBatch {
        use arrow_array::{Int64Array, StringArray, TimestampMicrosecondArray};
        use arrow_schema::TimeUnit;

        let schema = Arc::new(Schema::new(vec![
            Field::new(
                "timestamp",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            ),
            Field::new("value", DataType::Int64, false),
            Field::new("part", DataType::Utf8, false),
        ]));
        let timestamps: ArrayRef = Arc::new(TimestampMicrosecondArray::from(
            (start..start + len)
                .map(|s| s * 1_000_000)
                .collect::<Vec<_>>(),
        ));
        let values: ArrayRef = Arc::new(Int64Array::from((start..start + len).collect::<Vec<_>>()));
        let parts: ArrayRef = Arc::new(StringArray::from(vec![part; len as usize]));
        RecordBatch::try_new(schema, vec![timestamps, values, parts]).unwrap()
    }

    /// Four files across two partition values: every file sorted by timestamp,
    /// non-overlapping within a partition, overlapping across partitions — so
    /// `ORDER BY part, timestamp` is only answerable without a sort by
    /// regrouping the files per partition value.
    async fn partitioned_sorted_table() -> crate::DeltaTable {
        use crate::protocol::SaveMode;

        let mut table = crate::DeltaTable::new_in_memory()
            .write(vec![write_batch("A", 0, 100)])
            .with_partition_columns(vec!["part"])
            .with_save_mode(SaveMode::Append)
            .await
            .unwrap();
        for (part, start) in [("A", 100), ("A", 200), ("B", 50)] {
            table = table
                .write(vec![write_batch(part, start, 100)])
                .with_save_mode(SaveMode::Append)
                .await
                .unwrap();
        }
        table
    }

    /// Sort-pushdown state is only valid for the file grouping it was computed
    /// for, and `per_partition_stats` is indexed by execution partition.
    /// Swapping in a child with a different partition count must drop the
    /// advertised ordering — no `SortExec` remains above to correct it.
    #[tokio::test]
    async fn with_new_children_drops_pushdown_state_when_partition_count_changes() {
        use datafusion::physical_expr::Partitioning;
        use datafusion::physical_plan::repartition::RepartitionExec;
        use datafusion::physical_plan::{
            ExecutionPlan, ExecutionPlanProperties, SortOrderPushdownResult,
        };

        use crate::delta_datafusion::{FileSortColumn, create_session};

        let table = partitioned_sorted_table().await;
        let ctx = create_session().into_inner();
        let provider = table
            .table_provider()
            .with_file_sort_order([FileSortColumn::asc("timestamp")])
            .await
            .unwrap();

        let scan = provider.scan(&ctx.state(), None, &[], None).await.unwrap();
        let schema = scan.schema();
        let sort_col = |name: &str| {
            PhysicalSortExpr::new(
                Arc::new(Column::new(name, schema.index_of(name).unwrap())),
                SortOptions {
                    descending: false,
                    nulls_first: false,
                },
            )
        };
        let order = vec![sort_col("part"), sort_col("timestamp")];

        let pushed = match scan.try_pushdown_sort(&order).unwrap() {
            SortOrderPushdownResult::Exact { inner } => inner,
            other => panic!("expected an exact pushdown, got {other:?}"),
        };

        let leads_with_part = |plan: &Arc<dyn ExecutionPlan>| {
            plan.properties()
                .equivalence_properties()
                .oeq_class()
                .iter()
                .any(|ordering| {
                    ordering
                        .iter()
                        .next()
                        .and_then(|sort_expr| sort_expr.expr.downcast_ref::<Column>())
                        .is_some_and(|col| col.name() == "part")
                })
        };
        assert!(
            leads_with_part(&pushed),
            "a successful pushdown should advertise a `part`-leading ordering"
        );

        let child = Arc::clone(pushed.children()[0]);
        let repartitioned = Arc::new(
            RepartitionExec::try_new(
                child,
                Partitioning::RoundRobinBatch(pushed.output_partitioning().partition_count() + 1),
            )
            .unwrap(),
        );
        let swapped = pushed.with_new_children(vec![repartitioned]).unwrap();

        assert!(
            !leads_with_part(&swapped),
            "stale `part`-leading ordering survived a partition-count change"
        );
    }

    #[tokio::test]
    async fn e2e_partition_prefix_sort_avoids_sort_and_uses_progressive_eval() {
        use arrow_array::cast::AsArray;
        use arrow_array::types::TimestampMicrosecondType;

        use crate::delta_datafusion::{FileSortColumn, create_session};

        let table = partitioned_sorted_table().await;
        let ctx = create_session().into_inner();
        let provider = table
            .table_provider()
            .with_file_sort_order([FileSortColumn::asc("timestamp")])
            .await
            .unwrap();
        ctx.register_table("t", provider).unwrap();

        let df = ctx
            .sql("SELECT part, \"timestamp\", value FROM t ORDER BY part, \"timestamp\"")
            .await
            .unwrap();
        let plan = df.create_physical_plan().await.unwrap();
        let rendered = datafusion::physical_plan::displayable(plan.as_ref())
            .indent(true)
            .to_string();
        assert!(
            !rendered.contains("SortExec"),
            "expected no SortExec:\n{rendered}"
        );
        assert!(
            rendered.contains("ProgressiveEvalExec"),
            "expected ProgressiveEvalExec:\n{rendered}"
        );

        let batches = datafusion::physical_plan::collect(plan, ctx.task_ctx())
            .await
            .unwrap();
        let mut keys: Vec<(String, i64)> = Vec::new();
        for batch in &batches {
            let parts = arrow_cast::cast(batch.column(0), &arrow_schema::DataType::Utf8).unwrap();
            let parts = parts.as_string::<i32>();
            let timestamps = batch
                .column(1)
                .as_primitive::<TimestampMicrosecondType>()
                .values();
            for (part, ts) in parts.iter().zip(timestamps.iter()) {
                keys.push((part.unwrap().to_string(), *ts));
            }
        }
        assert_eq!(keys.len(), 400);
        assert!(
            keys.windows(2).all(|pair| pair[0] <= pair[1]),
            "results are not ordered by (part, timestamp)"
        );
    }

    #[test]
    fn chunk_buckets_allocates_without_spanning() {
        let a: Vec<_> = (0..6).map(|i| file(&format!("a{i}"), i, i, 0)).collect();
        let b: Vec<_> = (0..2).map(|i| file(&format!("b{i}"), i, i, 0)).collect();
        let groups = chunk_buckets(&[a, b], 4);
        // Every group's files come from a single bucket prefix.
        for group in &groups {
            let prefixes: std::collections::HashSet<char> = group
                .iter()
                .map(|f| f.object_meta.location.to_string().chars().next().unwrap())
                .collect();
            assert_eq!(prefixes.len(), 1);
        }
        assert_eq!(groups.iter().map(FileGroup::len).sum::<usize>(), 8);
    }
}
