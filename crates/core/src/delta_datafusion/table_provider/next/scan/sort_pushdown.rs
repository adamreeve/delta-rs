//! Sort pushdown implementation for [`DeltaScanExec`](super::exec::DeltaScanExec).
//!
//! DataFusion's `PushdownSort` physical optimizer rule allows regrouping files to
//! satisfy a query order and remove the need for a sort. This module handles this
//! regrouping for queries where the sort order starts with partition columns, and
//! any remaining sort expressions are a prefix of the declared file sort order.
//!
//! * Every data file belongs to exactly one partition, so within a file every
//!   partition column is constant. A file sorted by the declared file sort order
//!   is therefore also sorted by `[<any partition columns…>, <file sort order…>]`.
//! * Partition-column values are known exactly per file, so files can be
//!   bucketed by partition-column and ordered based on the file sort order, when
//!   the files are non-overlapping with respect to the sort order.
//!
//! The resulting file groups are mutually non-overlapping and range-ordered on
//! the combined ordering, so [`DeltaScanExec`](super::exec::DeltaScanExec)
//! advertises it as an output ordering; the `SortExec` is removed and the
//! `SortPreservingMergeExec` above it is later rewritten to a
//! `ProgressiveEvalExec` by [`ProgressiveEvalRule`](super::super::ProgressiveEvalRule).

use std::cmp::Ordering;
use std::sync::Arc;

use arrow_schema::{DataType, SchemaRef, SortOptions};
use datafusion::common::{ColumnStatistics, HashMap, Result, stats::Precision};
use datafusion::physical_expr::expressions::Column;
use datafusion::physical_expr::{LexOrdering, PhysicalSortExpr};
use datafusion::scalar::ScalarValue;
use datafusion_datasource::PartitionedFile;
use datafusion_datasource::file_groups::FileGroup;

use super::{
    DeltaPartitionValues, MAX_PARTITION_DICT_CARDINALITY, chunk_ordered_files,
    null_free_ordering_prefix, order_files_if_non_overlapping,
};

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
    /// Index of this column in the table's partition columns, i.e. into the
    /// [`DeltaPartitionValues`] attached to each file.
    position: usize,
    options: SortOptions,
}

/// A requested ordering this scan can satisfy by regrouping its files: a
/// non-empty prefix of partition columns, followed by a (possibly empty) prefix
/// of the declared file sort order.
pub(super) struct OrderShape {
    prefix: Vec<PrefixColumn>,
    /// The suffix, expressed over the parquet read schema, or `None` when the
    /// requested ordering is partition columns only.
    suffix: Option<LexOrdering>,
}

/// Compare two partition-prefix value tuples under the prefix column options.
///
/// Returns `None` when a pair of values is incomparable.
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

/// Classify `order` as a partition-column prefix plus a file-sort-order suffix,
/// or `None` when this scan cannot satisfy it by regrouping.
///
/// * `output_schema` – the scan's logical output schema (`order` is bound to it).
/// * `parquet_read_schema` – physical file columns, which `file_sort_order` is
///   bound to; also the prefix of the file scan's table schema, so its column
///   indices address `PartitionedFile` statistics directly.
/// * `partition_column_names` – logical partition columns, in table order.
/// * `file_sort_order` – resolved per-file ordering over `parquet_read_schema`.
pub(super) fn analyze_order(
    order: &LexOrdering,
    output_schema: &SchemaRef,
    parquet_read_schema: &SchemaRef,
    partition_column_names: &[String],
    file_sort_order: Option<&LexOrdering>,
) -> Option<OrderShape> {
    if partition_column_names.is_empty() {
        return None;
    }
    let column_name = |schema: &SchemaRef, sort_expr: &PhysicalSortExpr| -> Option<String> {
        let col = sort_expr.expr.downcast_ref::<Column>()?;
        Some(schema.fields().get(col.index())?.name().clone())
    };

    // Split the ordering at the first non-partition column.
    let mut prefix = Vec::new();
    for sort_expr in order.iter() {
        let name = column_name(output_schema, sort_expr)?;
        let Some(position) = partition_column_names.iter().position(|p| *p == name) else {
            break;
        };
        prefix.push(PrefixColumn {
            name,
            position,
            options: sort_expr.options,
        });
    }
    if prefix.is_empty() {
        // Sort order does not start with partition columns, this can't
        // be handled by a file regrouping.
        return None;
    }
    let suffix_exprs = &order[prefix.len()..];
    if suffix_exprs.is_empty() {
        return Some(OrderShape {
            prefix,
            suffix: None,
        });
    }

    // The suffix must match a prefix of the declared file sort order, column for
    // column and direction for direction, re-expressed over the read schema.
    let file_sort_order = file_sort_order?;
    if suffix_exprs.len() > file_sort_order.len() {
        return None;
    }
    let mut suffix = Vec::with_capacity(suffix_exprs.len());
    for (suffix_expr, file_sort_expr) in suffix_exprs.iter().zip(file_sort_order.iter()) {
        let suffix_name = column_name(output_schema, suffix_expr)?;
        // A partition column after the prefix cannot be honored by regrouping:
        // the files are not ordered on it.
        if partition_column_names.contains(&suffix_name) {
            return None;
        }
        let index = file_sort_expr.expr.downcast_ref::<Column>()?.index();
        let file_sort_name = parquet_read_schema.fields().get(index)?.name();
        if *file_sort_name != suffix_name || suffix_expr.options != file_sort_expr.options {
            return None;
        }
        suffix.push(PhysicalSortExpr::new(
            Arc::new(Column::new(file_sort_name, index)),
            suffix_expr.options,
        ));
    }

    Some(OrderShape {
        prefix,
        suffix: LexOrdering::new(suffix),
    })
}

/// A contiguous run of whole buckets (or one slice of a single bucket) that
/// becomes one execution partition, tagged with the partition-value range it
/// spans.
///
/// The keys are the range endpoints under the requested ordering, not
/// per-column minima and maxima: for a descending column the start key holds
/// the larger value. A run only ever spans several keys in the last prefix
/// column (see [`pack_buckets`]), so per-column extrema are recoverable by
/// swapping the two for a descending column.
struct BucketGroup {
    files: Vec<PartitionedFile>,
    /// Prefix key of the first bucket in the run.
    start_key: Vec<ScalarValue>,
    /// Prefix key of the last bucket in the run.
    end_key: Vec<ScalarValue>,
}

/// Files sharing one partition-prefix key, ordered on the suffix.
struct Bucket {
    key: Vec<ScalarValue>,
    files: Vec<PartitionedFile>,
}

/// Regroup `files` so that reading each group in order yields the ordering
/// described by `shape`, or return `None` when that cannot be guaranteed (the
/// caller then reports `Unsupported`).
///
/// * `parquet_read_schema` – physical file columns; its indices address
///   `PartitionedFile` statistics directly.
/// * `parquet_table_schema` – the file scan's full table schema.
/// * `target_groups` – desired execution-partition count.
pub(super) fn plan_sort_pushdown(
    shape: &OrderShape,
    parquet_read_schema: &SchemaRef,
    parquet_table_schema: &SchemaRef,
    files: Vec<PartitionedFile>,
    target_groups: usize,
) -> Result<Option<SortPushdownPlan>> {
    if files.is_empty() {
        return Ok(None);
    }
    let prefix = &shape.prefix;

    // --- Pair every file with its exact partition-prefix key. ---
    // Sort a lightweight (key, index) permutation rather than the large file objects.
    let mut keyed: Vec<(Vec<ScalarValue>, usize)> = Vec::with_capacity(files.len());
    let mut key_types: Option<Vec<DataType>> = None;
    for (index, file) in files.iter().enumerate() {
        let Some(values) = file.extensions.get::<DeltaPartitionValues>() else {
            return Ok(None);
        };
        let mut key = Vec::with_capacity(prefix.len());
        for col in prefix {
            match values.0.get(col.position) {
                // A null partition value cannot be ordered against non-null ones
                // via min/max statistics.
                Some(value) if !value.is_null() => key.push(value.clone()),
                _ => return Ok(None),
            }
        }
        // `ScalarValue::partial_cmp` is total within one non-nested type but
        // fails across variants, and `sort_by` panics on a comparator that is
        // not a total order. Require every key to share the first key's
        // per-column types so the sort below cannot see an incomparable pair.
        match &key_types {
            None => {
                let types: Vec<DataType> = key.iter().map(ScalarValue::data_type).collect();
                if types.iter().any(DataType::is_nested) {
                    return Ok(None);
                }
                key_types = Some(types);
            }
            Some(types) => {
                if !key
                    .iter()
                    .map(ScalarValue::data_type)
                    .eq(types.iter().cloned())
                {
                    return Ok(None);
                }
            }
        }
        keyed.push((key, index));
    }
    keyed.sort_by(|a, b| {
        cmp_prefix(&a.0, &b.0, prefix).expect("keys share a non-nested type per column")
    });

    // --- Cut the sorted files into buckets of equal prefix key. ---
    // One comparator decides both the bucket boundary and its validity: equal
    // keys extend the current bucket and a strict step opens a new one; the
    // keys were sorted with the same comparator, so any other outcome is a
    // backstop, not an expected path.
    let mut slots: Vec<Option<PartitionedFile>> = files.into_iter().map(Some).collect();
    let mut buckets: Vec<Bucket> = Vec::new();
    for (key, index) in keyed {
        let file = slots[index].take().expect("each file is claimed once");
        match buckets.last_mut() {
            None => buckets.push(Bucket {
                key,
                files: vec![file],
            }),
            Some(last) => match cmp_prefix(&last.key, &key, prefix) {
                Some(Ordering::Equal) => last.files.push(file),
                Some(Ordering::Less) => buckets.push(Bucket {
                    key,
                    files: vec![file],
                }),
                _ => return Ok(None),
            },
        }
    }

    // --- Order each bucket on the suffix, and require mutual non-overlap. ---
    if let Some(suffix) = shape.suffix.as_ref() {
        for bucket in &mut buckets {
            if bucket.files.len() < 2 {
                continue;
            }
            // Concatenating several files into one group interleaves each file's
            // nulls into the middle of the group's stream, which min/max cannot
            // detect, so every suffix column must be provably null-free.
            let null_free = null_free_ordering_prefix(suffix, parquet_read_schema, &bucket.files);
            if null_free.is_none_or(|p| p.len() < suffix.len()) {
                return Ok(None);
            }
            let flat = vec![FileGroup::new(std::mem::take(&mut bucket.files))];
            match order_files_if_non_overlapping(&flat, suffix, parquet_table_schema) {
                Some(ordered) => bucket.files = ordered,
                None => return Ok(None),
            }
        }
    }

    // --- Cut the buckets into groups and read the statistics off their keys. ---
    let groups = chunk_buckets(buckets, target_groups);
    let (file_groups, per_partition_stats) = groups
        .into_iter()
        .map(|group| {
            let stats = prefix
                .iter()
                .enumerate()
                .map(|(i, col)| {
                    // The keys are the group's range endpoints under the
                    // requested ordering, so for a descending column the start
                    // key is the larger value.
                    let (min, max) = if col.options.descending {
                        (&group.end_key[i], &group.start_key[i])
                    } else {
                        (&group.start_key[i], &group.end_key[i])
                    };
                    (
                        col.name.clone(),
                        ColumnStatistics {
                            null_count: Precision::Exact(0),
                            min_value: Precision::Exact(min.clone()),
                            max_value: Precision::Exact(max.clone()),
                            ..Default::default()
                        },
                    )
                })
                .collect();
            (FileGroup::from(group.files), stats)
        })
        .unzip();

    Ok(Some(SortPushdownPlan {
        file_groups,
        per_partition_stats,
    }))
}

/// Cut ordered, mutually non-overlapping buckets into roughly `target` groups.
///
/// Group boundaries always fall on bucket boundaries, so each group spans a
/// contiguous run of whole buckets and consecutive groups take a strict step on
/// the partition prefix — which is what lets `ProgressiveEvalRule` prove the
/// execution partitions disjoint. When there are more buckets than groups they
/// are packed together; when there are fewer, the largest are split.
///
/// The one exception is a single bucket holding more files than the file-id
/// partition dictionary can key, which is split further; every resulting group
/// still carries that bucket's key, so its statistics stay exact.
fn chunk_buckets(buckets: Vec<Bucket>, target: usize) -> Vec<BucketGroup> {
    let target = target.max(1);
    let total_files: usize = buckets.iter().map(|bucket| bucket.files.len()).sum();
    if total_files == 0 {
        return Vec::new();
    }

    if buckets.len() >= target {
        return pack_buckets(buckets, target, total_files);
    }

    // Fewer buckets than groups: split each bucket, giving it a share of the
    // group budget proportional to its file count and at least one group.
    let mut out = Vec::with_capacity(target);
    let mut groups_left = target;
    let mut files_left = total_files;
    for bucket in buckets {
        let files = bucket.files.len();
        let share = (groups_left * files).div_ceil(files_left).clamp(1, files);
        out.extend(
            chunk_ordered_files(bucket.files, share)
                .into_iter()
                .map(|group| BucketGroup {
                    files: group.into_inner(),
                    start_key: bucket.key.clone(),
                    end_key: bucket.key.clone(),
                }),
        );
        groups_left = groups_left.saturating_sub(share).max(1);
        files_left -= files;
    }
    out
}

/// Pack contiguous runs of whole buckets into `target` groups, balanced by file
/// count. A run is also cut when it would outgrow the file-id dictionary, or
/// when the next bucket differs in a prefix column other than the last.
///
/// Always cutting runs on changes in prefix columns other than the last is
/// required so that the min and max statistics can be determined exactly
/// from the start and end key values of the BucketGroup.
fn pack_buckets(buckets: Vec<Bucket>, target: usize, total_files: usize) -> Vec<BucketGroup> {
    let mut out: Vec<BucketGroup> = Vec::with_capacity(target);
    let mut groups_left = target;
    let mut files_left = total_files;
    let mut run: Option<BucketGroup> = None;
    let mut buckets_left = buckets.len();

    /// Emit the open run, if any, and charge it against the remaining budget.
    fn close(
        run: &mut Option<BucketGroup>,
        out: &mut Vec<BucketGroup>,
        files_left: &mut usize,
        groups_left: &mut usize,
    ) {
        if let Some(closed) = run.take() {
            *files_left -= closed.files.len();
            *groups_left = groups_left.saturating_sub(1).max(1);
            out.push(closed);
        }
    }

    for bucket in buckets {
        buckets_left -= 1;
        let files = bucket.files.len();

        // A bucket too large for the dictionary key space is split on its own;
        // every piece keeps the bucket's key, so its statistics stay exact.
        if files > MAX_PARTITION_DICT_CARDINALITY {
            close(&mut run, &mut out, &mut files_left, &mut groups_left);
            out.extend(
                chunk_ordered_files(bucket.files, files.div_ceil(MAX_PARTITION_DICT_CARDINALITY))
                    .into_iter()
                    .map(|group| BucketGroup {
                        files: group.into_inner(),
                        start_key: bucket.key.clone(),
                        end_key: bucket.key.clone(),
                    }),
            );
            groups_left = groups_left.saturating_sub(1).max(1);
            files_left -= files;
            continue;
        }

        // Only the last prefix column is allowed to change within a group.
        let leading = bucket.key.len() - 1;
        match run.as_mut() {
            Some(open)
                if open.files.len() + files <= MAX_PARTITION_DICT_CARDINALITY
                    && open.end_key[..leading] == bucket.key[..leading] =>
            {
                open.files.extend(bucket.files);
                open.end_key = bucket.key;
            }
            _ => {
                close(&mut run, &mut out, &mut files_left, &mut groups_left);
                run = Some(BucketGroup {
                    files: bucket.files,
                    start_key: bucket.key.clone(),
                    end_key: bucket.key,
                });
            }
        }

        // Close the run once it has its share of the files, or once every
        // remaining bucket is needed to fill a remaining group.
        let open = run.as_ref().expect("a run is open");
        let share = files_left.div_ceil(groups_left);
        if open.files.len() >= share || buckets_left < groups_left {
            close(&mut run, &mut out, &mut files_left, &mut groups_left);
        }
    }
    out.extend(run);
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

    fn desc(index: usize, name: &str) -> PhysicalSortExpr {
        PhysicalSortExpr::new(
            Arc::new(Column::new(name, index)),
            SortOptions {
                descending: true,
                nulls_first: true,
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

    /// A file carrying its synthetic file-id partition value, its Delta
    /// partition values, and exact timestamp min/max statistics (index 0 of the
    /// parquet table schema).
    fn file(
        url: &str,
        part: ScalarValue,
        ts_min: i64,
        ts_max: i64,
        ts_nulls: usize,
    ) -> PartitionedFile {
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
        file.extensions.insert(DeltaPartitionValues(vec![part]));
        file
    }

    fn utf8(part: &str) -> ScalarValue {
        ScalarValue::Utf8(Some(part.to_string()))
    }

    struct Fixture {
        files: Vec<PartitionedFile>,
    }

    impl Fixture {
        /// `specs` is `(url, part, ts_min, ts_max)`.
        fn new(specs: &[(&str, ScalarValue, i64, i64)]) -> Self {
            Self {
                files: specs
                    .iter()
                    .map(|(url, part, ts_min, ts_max)| file(url, part.clone(), *ts_min, *ts_max, 0))
                    .collect(),
            }
        }

        fn plan(
            &self,
            order: &[PhysicalSortExpr],
            file_sort_order: Option<&LexOrdering>,
            target_groups: usize,
        ) -> Option<SortPushdownPlan> {
            let order = LexOrdering::new(order.to_vec()).unwrap();
            let shape = analyze_order(
                &order,
                &output_schema(),
                &parquet_read_schema(),
                &["part".to_string()],
                file_sort_order,
            )?;
            plan_sort_pushdown(
                &shape,
                &parquet_read_schema(),
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
            ("a2", utf8("A"), 200, 299),
            ("a0", utf8("A"), 0, 99),
            ("b0", utf8("B"), 50, 149),
            ("a1", utf8("A"), 100, 199),
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
            ("a0", utf8("A"), 0, 99),
            ("a1", utf8("A"), 100, 199),
            ("a2", utf8("A"), 200, 299),
            ("b0", utf8("B"), 50, 149),
        ]);
        let order = vec![asc(0, "part"), asc(1, "timestamp")];

        // Fewer target groups than files: buckets are split but a group must
        // still not mix partition values.
        let plan = fixture
            .plan(&order, Some(&file_sort_order()), 2)
            .expect("expected a pushdown plan");

        for (group, stats) in plan.file_groups.iter().zip(&plan.per_partition_stats) {
            let parts: std::collections::HashSet<_> = group
                .iter()
                .map(|f| f.extensions.get::<DeltaPartitionValues>().unwrap().0[0].clone())
                .collect();
            assert_eq!(parts.len(), 1, "a group spans two partition values");
            // A single-partition group reports that value as an exact point range.
            let stat = &stats["part"];
            assert_eq!(stat.min_value, stat.max_value);
        }
    }

    #[test]
    fn overlapping_files_within_a_partition_are_not_supported() {
        let fixture = Fixture::new(&[
            ("a0", utf8("A"), 0, 150),
            ("a1", utf8("A"), 100, 199),
            ("b0", utf8("B"), 0, 99),
        ]);
        let order = vec![asc(0, "part"), asc(1, "timestamp")];

        assert!(fixture.plan(&order, Some(&file_sort_order()), 4).is_none());
    }

    #[test]
    fn incomparable_partition_values_are_not_supported() {
        // Mismatched `ScalarValue` variants for one partition column are
        // incomparable, so the best-effort sort cannot order them. Without the
        // strict step check when cutting buckets they would be concatenated in
        // an arbitrary order while the scan advertises `[part, timestamp]` as an
        // output ordering.
        let fixture = Fixture::new(&[
            ("a0", utf8("A"), 0, 99),
            ("b0", ScalarValue::Int64(Some(1)), 100, 199),
        ]);
        let order = vec![asc(0, "part"), asc(1, "timestamp")];

        assert!(fixture.plan(&order, Some(&file_sort_order()), 4).is_none());
    }

    #[test]
    fn many_incomparable_partition_values_do_not_panic_the_sort() {
        // Sorting mixed-variant keys with a comparator that collapses
        // incomparable pairs to `Equal` is not a total order, which rustc's
        // sort implementation detects and panics on for inputs large enough to
        // leave the insertion-sort path (this exact sequence did). The type
        // check while building keys must reject the pushdown before the sort
        // runs.
        let parts = [
            utf8("p034774"),
            ScalarValue::Int64(Some(44153)),
            ScalarValue::Int64(Some(41196)),
            ScalarValue::Int64(Some(92870)),
            utf8("p011034"),
            utf8("p039795"),
            utf8("p067130"),
            ScalarValue::Int64(Some(86902)),
            utf8("p098089"),
            utf8("p046746"),
            ScalarValue::Int64(Some(20123)),
            ScalarValue::Int64(Some(30802)),
            ScalarValue::Int64(Some(47452)),
            ScalarValue::Int64(Some(58400)),
            utf8("p087034"),
            ScalarValue::Int64(Some(44812)),
            utf8("p084890"),
            utf8("p070495"),
            utf8("p093332"),
            ScalarValue::Int64(Some(29365)),
            ScalarValue::Int64(Some(67627)),
        ];
        let specs: Vec<(String, ScalarValue, i64, i64)> = parts
            .into_iter()
            .enumerate()
            .map(|(i, part)| {
                let i = i as i64;
                (format!("f{i:02}"), part, i * 100, i * 100 + 99)
            })
            .collect();
        let specs: Vec<(&str, ScalarValue, i64, i64)> = specs
            .iter()
            .map(|(url, part, lo, hi)| (url.as_str(), part.clone(), *lo, *hi))
            .collect();
        let fixture = Fixture::new(&specs);
        let order = vec![asc(0, "part"), asc(1, "timestamp")];

        assert!(fixture.plan(&order, Some(&file_sort_order()), 4).is_none());
    }

    #[test]
    fn nulls_in_a_multi_file_bucket_suffix_are_not_supported() {
        let mut fixture = Fixture::new(&[("a0", utf8("A"), 0, 99), ("a1", utf8("A"), 100, 199)]);
        // Give the second file a nullable-looking timestamp column with nulls.
        fixture.files[1] = file("a1", utf8("A"), 100, 199, 3);
        let order = vec![asc(0, "part"), asc(1, "timestamp")];

        assert!(fixture.plan(&order, Some(&file_sort_order()), 4).is_none());
    }

    #[test]
    fn leading_data_column_is_not_supported() {
        let fixture = Fixture::new(&[("a0", utf8("A"), 0, 99), ("b0", utf8("B"), 0, 99)]);
        let order = vec![asc(1, "timestamp"), asc(0, "part")];

        assert!(fixture.plan(&order, Some(&file_sort_order()), 4).is_none());
    }

    #[test]
    fn suffix_must_match_the_declared_file_sort_order() {
        let fixture = Fixture::new(&[("a0", utf8("A"), 0, 99), ("b0", utf8("B"), 0, 99)]);
        // `value` is not the declared file sort column.
        let order = vec![asc(0, "part"), asc(2, "value")];

        assert!(fixture.plan(&order, Some(&file_sort_order()), 4).is_none());
    }

    #[test]
    fn partition_only_ordering_needs_no_file_sort_order() {
        let fixture = Fixture::new(&[
            ("b1", utf8("B"), 0, 99),
            ("a0", utf8("A"), 0, 99),
            ("b0", utf8("B"), 0, 99),
        ]);
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
        let fixture = Fixture::new(&[("a0", utf8("A"), 0, 99), ("b0", utf8("B"), 0, 99)]);
        let order = vec![desc(0, "part"), asc(1, "timestamp")];

        let plan = fixture
            .plan(&order, Some(&file_sort_order()), 4)
            .expect("expected a pushdown plan");
        let flat: Vec<_> = plan.file_groups.iter().flat_map(group_urls).collect();
        assert_eq!(flat, vec!["b0", "a0"]);
    }

    /// Natural minimum and maximum of one partition column over the files a
    /// group actually holds.
    fn actual_range(group: &FileGroup, position: usize) -> (ScalarValue, ScalarValue) {
        let mut values: Vec<ScalarValue> = group
            .iter()
            .map(|f| f.extensions.get::<DeltaPartitionValues>().unwrap().0[position].clone())
            .collect();
        values.sort_by(|a, b| a.partial_cmp(b).expect("comparable partition values"));
        (
            values.first().unwrap().clone(),
            values.last().unwrap().clone(),
        )
    }

    /// Assert every prefix column's published statistics are the natural
    /// extrema of the partition values the group actually holds.
    fn assert_stats_match_files(plan: &SortPushdownPlan, columns: &[&str]) {
        for (group, stats) in plan.file_groups.iter().zip(&plan.per_partition_stats) {
            for (position, name) in columns.iter().enumerate() {
                let (min, max) = actual_range(group, position);
                let stat = &stats[*name];
                assert_eq!(stat.min_value, Precision::Exact(min), "{name} min_value");
                assert_eq!(stat.max_value, Precision::Exact(max), "{name} max_value");
            }
        }
    }

    /// A group's keys are its range endpoints under the requested ordering, so
    /// for a descending column the first key is the group's *maximum*. Copying
    /// them into `min_value`/`max_value` as-is publishes an inverted range as
    /// `Precision::Exact` — `ProgressiveEvalRule` reads it back as
    /// `(start, end) = (max_value, min_value)` and gets the group's endpoints
    /// the wrong way round, and any other consumer sees `min > max`.
    #[test]
    fn descending_partition_prefix_statistics_are_not_inverted() {
        let fixture = Fixture::new(&[
            ("a0", utf8("A"), 0, 99),
            ("b0", utf8("B"), 0, 99),
            ("c0", utf8("C"), 0, 99),
        ]);
        let order = vec![desc(0, "part")];

        // More buckets than groups, so the leading two are packed into one run
        // that spans `C` … `B`.
        let plan = fixture
            .plan(&order, None, 2)
            .expect("expected a pushdown plan");

        assert_eq!(
            plan.file_groups.iter().map(group_urls).collect::<Vec<_>>(),
            vec![vec!["c0", "b0"], vec!["a0"]],
        );
        assert_stats_match_files(&plan, &["part"]);

        // How `ProgressiveEvalRule` decodes a descending column: the endpoints
        // must come back in the order the group's files are read.
        let stat = &plan.per_partition_stats[0]["part"];
        assert_eq!(stat.max_value, Precision::Exact(utf8("C")), "range start");
        assert_eq!(stat.min_value, Precision::Exact(utf8("B")), "range end");
    }

    fn two_column_output_schema() -> SchemaRef {
        Arc::new(Schema::new(vec![
            Field::new("part", DataType::Utf8, false),
            Field::new("sub", DataType::Int64, false),
            Field::new("timestamp", DataType::Int64, true),
            Field::new("value", DataType::Int64, true),
        ]))
    }

    fn two_column_file(url: &str, part: &str, sub: i64) -> PartitionedFile {
        let mut file = file(url, utf8(part), 0, 99, 0);
        file.extensions.insert(DeltaPartitionValues(vec![
            utf8(part),
            ScalarValue::Int64(Some(sub)),
        ]));
        file
    }

    fn plan_two_column(
        files: Vec<PartitionedFile>,
        order: &[PhysicalSortExpr],
        target_groups: usize,
    ) -> Option<SortPushdownPlan> {
        let order = LexOrdering::new(order.to_vec()).unwrap();
        let shape = analyze_order(
            &order,
            &two_column_output_schema(),
            &parquet_read_schema(),
            &["part".to_string(), "sub".to_string()],
            None,
        )?;
        plan_sort_pushdown(
            &shape,
            &parquet_read_schema(),
            &parquet_table_schema(),
            files,
            target_groups,
        )
        .unwrap()
    }

    /// A run may only span several keys in the *last* prefix column. A run from
    /// `[A, 2]` to `[B, 0]` is properly ordered, but its endpoints are not the
    /// extrema of anything: `sub` really covers `0..2` there, so no
    /// `ColumnStatistics` can describe both the range and where it starts.
    #[test]
    fn packed_runs_do_not_span_a_change_in_a_leading_prefix_column() {
        let files = vec![
            two_column_file("a1", "A", 1),
            two_column_file("a2", "A", 2),
            two_column_file("b0", "B", 0),
        ];
        let order = vec![asc(0, "part"), asc(1, "sub")];

        // One target group would otherwise pack all three buckets into one run.
        let plan = plan_two_column(files, &order, 1).expect("expected a pushdown plan");

        assert_eq!(
            plan.file_groups.iter().map(group_urls).collect::<Vec<_>>(),
            vec![vec!["a1", "a2"], vec!["b0"]],
        );
        assert_stats_match_files(&plan, &["part", "sub"]);
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
    /// Swapping in a child must drop the advertised ordering.
    #[tokio::test]
    async fn with_new_children_drops_pushdown_state() {
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
            "stale `part`-leading ordering survived a child change"
        );
    }

    /// `repartitioned` swaps in a re-split input; the cached plan properties
    /// were computed from the old input and must be rebuilt, or the exec
    /// advertises a stale partition count and parents execute too few
    /// partitions.
    #[tokio::test]
    async fn repartitioned_recomputes_partitioning() {
        use datafusion::config::ConfigOptions;
        use datafusion::physical_plan::{ExecutionPlan, ExecutionPlanProperties};

        use crate::delta_datafusion::create_session;

        let table = partitioned_sorted_table().await;
        let ctx = create_session().into_inner();
        // No declared file sort order: an ordered scan refuses re-splitting.
        let provider = table.table_provider().await.unwrap();
        let scan = provider.scan(&ctx.state(), None, &[], None).await.unwrap();
        let before = scan.output_partitioning().partition_count();

        let mut config = ConfigOptions::new();
        // The test files are tiny; split on any size.
        config.optimizer.repartition_file_min_size = 1;
        let repartitioned = scan
            .repartitioned(before + 4, &config)
            .unwrap()
            .expect("expected the scan to accept a repartition");

        let child_partitions = repartitioned.children()[0]
            .output_partitioning()
            .partition_count();
        assert_ne!(
            before, child_partitions,
            "the input did not change its partitioning; the test is inert"
        );
        assert_eq!(
            repartitioned.output_partitioning().partition_count(),
            child_partitions,
            "stale cached partitioning survived a repartition"
        );
    }

    /// Without pushed-down per-partition statistics, a request for one
    /// execution partition's statistics falls back to the table-wide
    /// aggregated partition-column stats. Those are valid bounds for the
    /// partition but must not claim exactness.
    #[tokio::test]
    async fn per_partition_statistics_fall_back_to_inexact_aggregates() {
        use datafusion::config::ConfigOptions;
        use datafusion::physical_plan::{ExecutionPlan, ExecutionPlanProperties};

        use crate::delta_datafusion::create_session;

        let table = partitioned_sorted_table().await;
        let ctx = create_session().into_inner();
        let provider = table.table_provider().await.unwrap();
        let scan = provider.scan(&ctx.state(), None, &[], None).await.unwrap();

        let mut config = ConfigOptions::new();
        config.optimizer.repartition_file_min_size = 1;
        let scan = scan
            .repartitioned(4, &config)
            .unwrap()
            .expect("expected the scan to accept a repartition");
        assert!(scan.output_partitioning().partition_count() > 1);
        let part_index = scan.schema().index_of("part").unwrap();

        let whole_scan = scan.partition_statistics(None).unwrap();
        assert!(
            matches!(
                whole_scan.column_statistics[part_index].min_value,
                Precision::Exact(_)
            ),
            "table-wide partition-column statistics should stay exact"
        );

        let one_partition = scan.partition_statistics(Some(0)).unwrap();
        for stat in [
            &one_partition.column_statistics[part_index].min_value,
            &one_partition.column_statistics[part_index].max_value,
        ] {
            assert!(
                !matches!(stat, Precision::Exact(_)),
                "table-wide aggregate published as exact for one partition: {stat:?}"
            );
        }
        assert!(
            !matches!(
                one_partition.column_statistics[part_index].null_count,
                Precision::Exact(_)
            ),
            "table-wide null count published as exact for one partition"
        );
    }

    #[test]
    fn chunk_buckets_splits_when_there_are_fewer_buckets_than_groups() {
        let bucket = |name: char, n: i64| Bucket {
            key: vec![utf8(&name.to_string())],
            files: (0..n)
                .map(|i| file(&format!("{name}{i}"), utf8(&name.to_string()), i, i, 0))
                .collect(),
        };
        let groups = chunk_buckets(vec![bucket('a', 6), bucket('b', 2)], 4);

        // Every group's files come from a single bucket.
        for group in &groups {
            let prefixes: std::collections::HashSet<char> = group
                .files
                .iter()
                .map(|f| f.object_meta.location.to_string().chars().next().unwrap())
                .collect();
            assert_eq!(prefixes.len(), 1);
            assert_eq!(group.start_key, group.end_key);
        }
        assert_eq!(groups.iter().map(|g| g.files.len()).sum::<usize>(), 8);
        assert!(groups.len() >= 2, "each bucket gets at least one group");
    }

    /// With more buckets than groups, whole buckets are packed together so a
    /// query selecting many partitions does not explode the scan's partition
    /// count. Groups stay bucket-aligned, so consecutive groups still take a
    /// strict step on the partition prefix.
    #[test]
    fn chunk_buckets_packs_whole_buckets_when_they_outnumber_groups() {
        let buckets: Vec<Bucket> = (0..20)
            .map(|i| {
                let key = ScalarValue::Int64(Some(i));
                Bucket {
                    key: vec![key.clone()],
                    files: vec![file(&format!("f{i}"), key, i, i, 0)],
                }
            })
            .collect();

        let groups = chunk_buckets(buckets, 4);

        assert_eq!(groups.len(), 4);
        assert_eq!(groups.iter().map(|g| g.files.len()).sum::<usize>(), 20);
        // Each group's key range is strictly after the previous group's.
        for pair in groups.windows(2) {
            assert!(
                pair[0].end_key[0] < pair[1].start_key[0],
                "group key ranges must take a strict step"
            );
        }
    }
}
