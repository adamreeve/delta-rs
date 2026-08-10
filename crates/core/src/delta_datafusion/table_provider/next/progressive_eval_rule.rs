//! Physical optimizer rule that replaces a merge of ordered partitions with
//! a plain concatenation.
//!
//! A [`SortPreservingMergeExec`] combines its input partitions into one globally
//! ordered stream. That merge compares rows across all partitions and executes every
//! partition up front.
//! If the partitions are non-overlapping with respect to the sort order, then
//! this merge is unnecessary, and we can stream the partitions one after another
//! using a [`ProgressiveEvalExec`].

use datafusion::common::config::ConfigOptions;
use datafusion::common::stats::Statistics;
use datafusion::common::tree_node::{Transformed, TransformedResult, TreeNode, TreeNodeRecursion};
use datafusion::common::{Result, ScalarValue};
use datafusion::physical_expr::expressions::Column;
use datafusion::physical_expr::{LexOrdering, Partitioning};
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::repartition::RepartitionExec;
use datafusion::physical_plan::sorts::sort::SortExec;
use datafusion::physical_plan::sorts::sort_preserving_merge::SortPreservingMergeExec;
use datafusion::physical_plan::{ExecutionPlan, ExecutionPlanProperties as _};

use super::progressive_eval::ProgressiveEvalExec;
use std::cmp::Ordering;
use std::sync::Arc;

/// Replace [`SortPreservingMergeExec`] with [`ProgressiveEvalExec`] when its
/// input partitions are mutually non-overlapping, range-ordered slices of the
/// merge ordering, so concatenating them already yields globally ordered
/// output. See the [module docs](self) for background.
#[derive(Debug, Default)]
pub struct ProgressiveEvalRule;

impl ProgressiveEvalRule {
    pub fn new() -> Self {
        Self
    }
}

impl PhysicalOptimizerRule for ProgressiveEvalRule {
    fn optimize(
        &self,
        plan: Arc<dyn ExecutionPlan>,
        _config: &ConfigOptions,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        plan.transform_down(|plan| {
            let Some(merge) =
                (plan.as_ref() as &dyn ExecutionPlan).downcast_ref::<SortPreservingMergeExec>()
            else {
                return Ok(Transformed::no(plan));
            };
            // Round-robin repartitioning inserted for parallelism defeats this
            // optimization: `RepartitionExec` reports all column statistics as
            // inexact, and interleaving batches destroys the per-partition
            // ranges anyway. A serial progressive evaluation gains nothing from
            // the extra partitions, so strip such repartitions and test whether
            // the stripped plan qualifies. If it does not, keep the original
            // plan (and its parallelism).
            let input = remove_parallelism_nodes(Arc::clone(merge.input()))?;
            // Stripping a repartition can only expose more ordering, but be
            // defensive: each partition of the new input must still be sorted
            // by the merge ordering for concatenation to be valid.
            if !input
                .equivalence_properties()
                .ordering_satisfy(merge.expr().iter().cloned())?
            {
                return Ok(Transformed::no(plan));
            }
            let Some(ranges) = ordered_partition_ranges(&input, merge.expr()) else {
                return Ok(Transformed::no(plan));
            };
            let replacement = ProgressiveEvalExec::new(input, Some(ranges), merge.fetch());
            Ok(Transformed::yes(Arc::new(replacement) as _))
        })
        .data()
    }

    fn name(&self) -> &str {
        "ProgressiveEvalRule"
    }

    fn schema_check(&self) -> bool {
        true
    }
}

/// Remove plan nodes that only exist to raise or repair parallelism from the
/// subtree feeding a merge, where they defeat this optimization without
/// benefiting a serial progressive evaluation:
///
/// - Round-robin [`RepartitionExec`] nodes are inserted purely to spread work
///   across partitions. Hash repartitions (which place rows deliberately) are
///   left alone.
/// - [`SortExec`] nodes whose input already satisfies their ordering are
///   typically left behind by the repartition removal: `EnforceSorting` adds
///   them to repair the ordering the repartition destroyed. Being blocking
///   operators, they would also forfeit the streaming behaviour of
///   [`ProgressiveEvalExec`]. Sorts with a fetch limit their output, so they
///   are kept.
///
/// Sorts are checked in a second pass so that each check sees the input's
/// ordering as recomputed after the repartition below it was removed.
/// Traversal stops at a nested [`SortPreservingMergeExec`], whose subtree is
/// considered on its own when the enclosing `transform_down` reaches it.
fn remove_parallelism_nodes(plan: Arc<dyn ExecutionPlan>) -> Result<Arc<dyn ExecutionPlan>> {
    let stripped = plan
        .transform_down(|plan| {
            let plan_ref = plan.as_ref() as &dyn ExecutionPlan;
            if let Some(repartition) = plan_ref.downcast_ref::<RepartitionExec>() {
                if matches!(repartition.partitioning(), Partitioning::RoundRobinBatch(_)) {
                    return Ok(Transformed::new(
                        Arc::clone(repartition.input()),
                        true,
                        TreeNodeRecursion::Continue,
                    ));
                }
            } else if plan_ref.downcast_ref::<SortPreservingMergeExec>().is_some() {
                return Ok(Transformed::new(plan, false, TreeNodeRecursion::Jump));
            }
            Ok(Transformed::no(plan))
        })
        .data()?;
    stripped
        .transform_down(|plan| {
            let plan_ref = plan.as_ref() as &dyn ExecutionPlan;
            if let Some(sort) = plan_ref.downcast_ref::<SortExec>() {
                if sort.fetch().is_none()
                    && sort.preserve_partitioning()
                    && sort
                        .input()
                        .equivalence_properties()
                        .ordering_satisfy(sort.expr().iter().cloned())?
                {
                    return Ok(Transformed::new(
                        Arc::clone(sort.input()),
                        true,
                        TreeNodeRecursion::Continue,
                    ));
                }
            } else if plan_ref.downcast_ref::<SortPreservingMergeExec>().is_some() {
                return Ok(Transformed::new(plan, false, TreeNodeRecursion::Jump));
            }
            Ok(Transformed::no(plan))
        })
        .data()
}

/// To be able to convert to a ProgressiveEval, we need the partitions to
/// be ordered with respect to each other.
/// If this is the case, return a vector of the (start, end) range for the first
/// sort term from each partition, otherwise return None.
///
/// Each partition boundary is checked by walking the sort columns: a strictly
/// ordered column proves the boundary (later columns are irrelevant), an equal
/// column defers to the next one, and an out-of-order column rejects. The
/// min/max statistics used for these comparisons exclude nulls, so a
/// comparison at a column is only valid when nulls cannot hide on the wrong
/// side of the boundary: nulls sorting last may lurk anywhere in the earlier
/// partition (including among rows tied on all preceding sort columns, which
/// they would follow), and nulls sorting first anywhere in the later one.
/// Columns after a strict break are never relied on, so their nulls are
/// harmless.
fn ordered_partition_ranges(
    plan: &Arc<dyn ExecutionPlan>,
    ordering: &LexOrdering,
) -> Option<Vec<(ScalarValue, ScalarValue)>> {
    let partition_count = plan.output_partitioning().partition_count();
    let mut prev_ends: Vec<ScalarValue> = Vec::new();
    let mut prev_null_counts: Vec<usize> = Vec::new();
    let mut first_col_ordering = Vec::with_capacity(partition_count);
    for partition_idx in 0..partition_count {
        let partition_stats = plan.partition_statistics(Some(partition_idx)).ok()?;
        let (starts, ends, null_counts) = get_ordering_stats(&partition_stats, ordering)?;
        if partition_idx != 0 {
            // Check partition is ordered correctly with respect to the previous partition
            for (i, sort_expr) in ordering.iter().enumerate() {
                // Reject nulls that could sort onto the wrong side of this
                // boundary; see the function docs.
                let boundary_null_count = if sort_expr.options.nulls_first {
                    null_counts[i]
                } else {
                    prev_null_counts[i]
                };
                if boundary_null_count != 0 {
                    return None;
                }
                // Incomparable values (partial_cmp is None) bail out rather
                // than being silently treated as equal.
                let cmp = starts[i].partial_cmp(&prev_ends[i])?;
                let cmp = if sort_expr.options.descending {
                    cmp.reverse()
                } else {
                    cmp
                };
                match cmp {
                    // In order
                    Ordering::Greater => break,
                    // Out of order
                    Ordering::Less => return None,
                    // Equal, need to check next sort expression
                    Ordering::Equal => continue,
                }
            }
        }
        first_col_ordering.push((starts[0].clone(), ends[0].clone()));
        prev_ends = ends;
        prev_null_counts = null_counts;
    }
    Some(first_col_ordering)
}

fn get_ordering_stats(
    stats: &Arc<Statistics>,
    ordering: &LexOrdering,
) -> Option<(Vec<ScalarValue>, Vec<ScalarValue>, Vec<usize>)> {
    let mut starts = Vec::with_capacity(ordering.len());
    let mut ends = Vec::with_capacity(ordering.len());
    let mut null_counts = Vec::with_capacity(ordering.len());

    for sort_expr in ordering.iter() {
        let column = sort_expr.expr.downcast_ref::<Column>()?;
        let col_stats = stats.column_statistics.get(column.index())?;
        // We require exact stats to guarantee no overlap in partition ranges.
        if !(col_stats.null_count.is_exact()?
            && col_stats.min_value.is_exact()?
            && col_stats.max_value.is_exact()?)
        {
            return None;
        }
        let (start, end) = if sort_expr.options.descending {
            (
                col_stats.max_value.get_value()?,
                col_stats.min_value.get_value()?,
            )
        } else {
            (
                col_stats.min_value.get_value()?,
                col_stats.max_value.get_value()?,
            )
        };
        // Stats may be null for all-null or empty partitions.
        // For now, don't try to optimize this case:
        if start.is_null() || end.is_null() {
            return None;
        }
        starts.push(start.clone());
        ends.push(end.clone());
        null_counts.push(*col_stats.null_count.get_value()?);
    }

    Some((starts, ends, null_counts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_schema::{DataType, Field, Schema, SchemaRef, SortOptions};
    use datafusion::common::stats::{ColumnStatistics, Precision};
    use datafusion::execution::{SendableRecordBatchStream, TaskContext};
    use datafusion::physical_expr::{EquivalenceProperties, Partitioning, PhysicalSortExpr};
    use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
    use datafusion::physical_plan::{DisplayAs, DisplayFormatType, PlanProperties};

    /// Leaf plan reporting fixed per-partition statistics; never executed.
    #[derive(Debug)]
    struct StatsExec {
        stats: Vec<Statistics>,
        cache: Arc<PlanProperties>,
    }

    impl StatsExec {
        fn new(stats: Vec<Statistics>) -> Arc<dyn ExecutionPlan> {
            Self::with_ordering(stats, None)
        }

        fn with_ordering(
            stats: Vec<Statistics>,
            ordering: Option<LexOrdering>,
        ) -> Arc<dyn ExecutionPlan> {
            let eq_properties = match ordering {
                Some(ordering) => {
                    EquivalenceProperties::new_with_orderings(test_schema(), vec![ordering])
                }
                None => EquivalenceProperties::new(test_schema()),
            };
            let cache = Arc::new(PlanProperties::new(
                eq_properties,
                Partitioning::UnknownPartitioning(stats.len()),
                EmissionType::Incremental,
                Boundedness::Bounded,
            ));
            Arc::new(Self { stats, cache })
        }
    }

    impl DisplayAs for StatsExec {
        fn fmt_as(
            &self,
            _t: DisplayFormatType,
            f: &mut std::fmt::Formatter<'_>,
        ) -> std::fmt::Result {
            write!(f, "StatsExec")
        }
    }

    impl ExecutionPlan for StatsExec {
        fn name(&self) -> &'static str {
            "StatsExec"
        }

        fn properties(&self) -> &Arc<PlanProperties> {
            &self.cache
        }

        fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
            vec![]
        }

        fn with_new_children(
            self: Arc<Self>,
            _children: Vec<Arc<dyn ExecutionPlan>>,
        ) -> Result<Arc<dyn ExecutionPlan>> {
            Ok(self)
        }

        fn execute(
            &self,
            _partition: usize,
            _context: Arc<TaskContext>,
        ) -> Result<SendableRecordBatchStream> {
            unimplemented!("StatsExec is only used for planning")
        }

        fn partition_statistics(&self, partition: Option<usize>) -> Result<Arc<Statistics>> {
            match partition {
                Some(idx) => Ok(Arc::new(self.stats[idx].clone())),
                None => Ok(Arc::new(Statistics::new_unknown(&self.schema()))),
            }
        }
    }

    fn test_schema() -> SchemaRef {
        Arc::new(Schema::new(vec![
            Field::new("t", DataType::Int64, true),
            Field::new("id", DataType::Int64, true),
        ]))
    }

    fn sort_expr(index: usize, name: &str, options: SortOptions) -> PhysicalSortExpr {
        PhysicalSortExpr::new(Arc::new(Column::new(name, index)), options)
    }

    fn asc(index: usize, name: &str) -> PhysicalSortExpr {
        sort_expr(
            index,
            name,
            SortOptions {
                descending: false,
                nulls_first: false,
            },
        )
    }

    fn desc(index: usize, name: &str) -> PhysicalSortExpr {
        sort_expr(
            index,
            name,
            SortOptions {
                descending: true,
                nulls_first: true,
            },
        )
    }

    fn exact_i64(min: i64, max: i64, null_count: usize) -> ColumnStatistics {
        ColumnStatistics {
            null_count: Precision::Exact(null_count),
            min_value: Precision::Exact(ScalarValue::Int64(Some(min))),
            max_value: Precision::Exact(ScalarValue::Int64(Some(max))),
            ..Default::default()
        }
    }

    fn partition(column_statistics: Vec<ColumnStatistics>) -> Statistics {
        Statistics {
            num_rows: Precision::Exact(10),
            total_byte_size: Precision::Exact(100),
            column_statistics,
        }
    }

    #[test]
    fn equal_first_column_boundary_ordered_by_second_column() {
        // The partitions share t = 100 on the boundary; the disjoint id
        // ranges disambiguate, so the check falls through to the second
        // sort column and accepts.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(0, 100, 0), exact_i64(0, 10, 0)]),
            partition(vec![exact_i64(100, 200, 0), exact_i64(11, 20, 0)]),
        ]);
        let ordering = LexOrdering::new(vec![asc(0, "t"), asc(1, "id")]).unwrap();

        let ranges = ordered_partition_ranges(&plan, &ordering).expect("expected ranges");
        assert_eq!(
            ranges,
            vec![
                (ScalarValue::Int64(Some(0)), ScalarValue::Int64(Some(100))),
                (ScalarValue::Int64(Some(100)), ScalarValue::Int64(Some(200))),
            ]
        );
    }

    #[test]
    fn equal_first_column_boundary_overlapping_second_column() {
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(0, 100, 0), exact_i64(0, 10, 0)]),
            partition(vec![exact_i64(100, 200, 0), exact_i64(5, 20, 0)]),
        ]);
        let ordering = LexOrdering::new(vec![asc(0, "t"), asc(1, "id")]).unwrap();

        assert!(ordered_partition_ranges(&plan, &ordering).is_none());
    }

    #[test]
    fn boundary_equal_on_all_sort_columns_is_accepted() {
        // min == prev max on every sort column bounds all rows of both
        // partitions, so concatenation is still (non-strictly) ordered.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(0, 100, 0), exact_i64(0, 10, 0)]),
            partition(vec![exact_i64(100, 200, 0), exact_i64(10, 20, 0)]),
        ]);
        let ordering = LexOrdering::new(vec![asc(0, "t"), asc(1, "id")]).unwrap();

        assert!(ordered_partition_ranges(&plan, &ordering).is_some());
    }

    #[test]
    fn nulls_only_allowed_in_last_partition_for_nulls_last() {
        let ordering = LexOrdering::new(vec![asc(0, "t")]).unwrap();

        // Nulls in the last partition sort after all values: accepted.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(0, 99, 0), exact_i64(0, 10, 0)]),
            partition(vec![exact_i64(100, 200, 2), exact_i64(0, 10, 0)]),
        ]);
        assert!(ordered_partition_ranges(&plan, &ordering).is_some());

        // Nulls in the first partition would surface mid-stream: rejected.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(0, 99, 2), exact_i64(0, 10, 0)]),
            partition(vec![exact_i64(100, 200, 0), exact_i64(0, 10, 0)]),
        ]);
        assert!(ordered_partition_ranges(&plan, &ordering).is_none());
    }

    #[test]
    fn nulls_only_allowed_in_first_partition_for_nulls_first() {
        let ordering = LexOrdering::new(vec![desc(0, "t")]).unwrap();

        // Descending partitions with nulls leading in the first: accepted.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(100, 200, 2), exact_i64(0, 10, 0)]),
            partition(vec![exact_i64(0, 99, 0), exact_i64(0, 10, 0)]),
        ]);
        assert!(ordered_partition_ranges(&plan, &ordering).is_some());

        // Nulls in the last partition sort before its values: rejected.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(100, 200, 0), exact_i64(0, 10, 0)]),
            partition(vec![exact_i64(0, 99, 2), exact_i64(0, 10, 0)]),
        ]);
        assert!(ordered_partition_ranges(&plan, &ordering).is_none());
    }

    #[test]
    fn nulls_in_deeper_sort_column_hidden_by_first_column_break() {
        // The middle partition carries a null in the second sort column. Its
        // boundary with the first partition is strict on the first column, so
        // the second column is never inspected for it. The boundary with the
        // last partition is equal on the first column and falls through to
        // the second: the middle partition's non-null max (4) < the last
        // partition's min (5) looks ordered, but the middle partition's null
        // rows sort after every non-null value (nulls last), so a row like
        // (20, NULL) would precede (20, 5) in the concatenation.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(0, 9, 0), exact_i64(0, 9, 0)]),
            partition(vec![exact_i64(10, 20, 0), exact_i64(0, 4, 1)]),
            partition(vec![exact_i64(20, 30, 0), exact_i64(5, 8, 0)]),
        ]);
        let ordering = LexOrdering::new(vec![asc(0, "t"), asc(1, "id")]).unwrap();

        assert!(ordered_partition_ranges(&plan, &ordering).is_none());
    }

    #[test]
    fn nulls_in_deeper_sort_column_harmless_when_boundaries_strict_on_first() {
        // Both of the middle partition's boundaries are strict on the first
        // column, so the second sort column is never relied on and its nulls
        // cannot surface out of order.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(0, 9, 0), exact_i64(0, 9, 0)]),
            partition(vec![exact_i64(10, 19, 0), exact_i64(0, 4, 1)]),
            partition(vec![exact_i64(20, 30, 0), exact_i64(5, 8, 0)]),
        ]);
        let ordering = LexOrdering::new(vec![asc(0, "t"), asc(1, "id")]).unwrap();

        assert!(ordered_partition_ranges(&plan, &ordering).is_some());
    }

    #[test]
    fn nulls_in_first_partition_with_all_equal_values_rejected() {
        // Every partition shares the same value on both sort columns, so no
        // boundary breaks early and every column is inspected. The first
        // partition's nulls (sorting last) would surface before the later
        // partitions' rows; the first boundary must reject them.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(5, 5, 0), exact_i64(7, 7, 1)]),
            partition(vec![exact_i64(5, 5, 0), exact_i64(7, 7, 0)]),
            partition(vec![exact_i64(5, 5, 0), exact_i64(7, 7, 0)]),
        ]);
        let ordering = LexOrdering::new(vec![asc(0, "t"), asc(1, "id")]).unwrap();

        assert!(ordered_partition_ranges(&plan, &ordering).is_none());
    }

    #[test]
    fn nulls_in_middle_partition_with_all_equal_values_rejected() {
        // As above, but the nulls sit in the middle partition: its boundary
        // with the *next* partition is the one that must reject them.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(5, 5, 0), exact_i64(7, 7, 0)]),
            partition(vec![exact_i64(5, 5, 0), exact_i64(7, 7, 1)]),
            partition(vec![exact_i64(5, 5, 0), exact_i64(7, 7, 0)]),
        ]);
        let ordering = LexOrdering::new(vec![asc(0, "t"), asc(1, "id")]).unwrap();

        assert!(ordered_partition_ranges(&plan, &ordering).is_none());
    }

    #[test]
    fn nulls_in_last_partition_with_all_equal_values_accepted() {
        // Nulls sorting last in the last partition stream at the very end of
        // the concatenation: correct, and there is no later boundary to
        // invalidate.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(5, 5, 0), exact_i64(7, 7, 0)]),
            partition(vec![exact_i64(5, 5, 0), exact_i64(7, 7, 0)]),
            partition(vec![exact_i64(5, 5, 0), exact_i64(7, 7, 1)]),
        ]);
        let ordering = LexOrdering::new(vec![asc(0, "t"), asc(1, "id")]).unwrap();

        assert!(ordered_partition_ranges(&plan, &ordering).is_some());
    }

    #[test]
    fn descending_partitions_out_of_order() {
        // Ascending partition layout under a descending ordering.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(0, 99, 0), exact_i64(0, 10, 0)]),
            partition(vec![exact_i64(100, 200, 0), exact_i64(0, 10, 0)]),
        ]);
        let ordering = LexOrdering::new(vec![desc(0, "t")]).unwrap();

        assert!(ordered_partition_ranges(&plan, &ordering).is_none());
    }

    #[test]
    fn incomparable_statistics_types_bail_out() {
        // Mismatched stat types across partitions are incomparable; they
        // must not be treated as an equal boundary.
        let utf8 = |value: &str| ScalarValue::Utf8(Some(value.to_string()));
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(0, 100, 0), exact_i64(0, 10, 0)]),
            partition(vec![
                ColumnStatistics {
                    null_count: Precision::Exact(0),
                    min_value: Precision::Exact(utf8("a")),
                    max_value: Precision::Exact(utf8("b")),
                    ..Default::default()
                },
                exact_i64(0, 10, 0),
            ]),
        ]);
        let ordering = LexOrdering::new(vec![asc(0, "t")]).unwrap();

        assert!(ordered_partition_ranges(&plan, &ordering).is_none());
    }

    #[test]
    fn inexact_statistics_bail_out() {
        let inexact = ColumnStatistics {
            null_count: Precision::Exact(0),
            min_value: Precision::Inexact(ScalarValue::Int64(Some(100))),
            max_value: Precision::Exact(ScalarValue::Int64(Some(200))),
            ..Default::default()
        };
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(0, 99, 0), exact_i64(0, 10, 0)]),
            partition(vec![inexact, exact_i64(0, 10, 0)]),
        ]);
        let ordering = LexOrdering::new(vec![asc(0, "t")]).unwrap();

        assert!(ordered_partition_ranges(&plan, &ordering).is_none());
    }

    #[test]
    fn null_statistics_values_bail_out() {
        // All-null or empty partitions report exact but null min/max values;
        // they prove nothing about the partition's range. An all-null first
        // partition under an ascending nulls-first ordering is the dangerous
        // layout: the null guard passes (the later partition has no nulls)
        // and a null scalar compares before any value, so without the
        // explicit bail-out the boundary would look ordered.
        let all_null = ColumnStatistics {
            null_count: Precision::Exact(10),
            min_value: Precision::Exact(ScalarValue::Int64(None)),
            max_value: Precision::Exact(ScalarValue::Int64(None)),
            ..Default::default()
        };
        let plan = StatsExec::new(vec![
            partition(vec![all_null, exact_i64(0, 10, 0)]),
            partition(vec![exact_i64(0, 99, 0), exact_i64(0, 10, 0)]),
        ]);
        let ordering = LexOrdering::new(vec![sort_expr(
            0,
            "t",
            SortOptions {
                descending: false,
                nulls_first: true,
            },
        )])
        .unwrap();

        assert!(ordered_partition_ranges(&plan, &ordering).is_none());
    }

    #[test]
    fn missing_column_statistics_bail_out() {
        // The ordering references a column index beyond the available
        // statistics; the lookup must bail out rather than panic.
        let plan = StatsExec::new(vec![
            partition(vec![exact_i64(0, 99, 0)]),
            partition(vec![exact_i64(100, 200, 0)]),
        ]);
        let ordering = LexOrdering::new(vec![asc(1, "id")]).unwrap();

        assert!(ordered_partition_ranges(&plan, &ordering).is_none());
    }

    fn t_asc_ordering() -> LexOrdering {
        LexOrdering::new(vec![asc(0, "t")]).unwrap()
    }

    /// Ordered scan with two non-overlapping partitions.
    fn non_overlapping_ordered_scan() -> Arc<dyn ExecutionPlan> {
        StatsExec::with_ordering(
            vec![
                partition(vec![exact_i64(0, 99, 0), exact_i64(0, 10, 0)]),
                partition(vec![exact_i64(100, 200, 0), exact_i64(0, 10, 0)]),
            ],
            Some(t_asc_ordering()),
        )
    }

    fn optimize(plan: Arc<dyn ExecutionPlan>) -> Arc<dyn ExecutionPlan> {
        ProgressiveEvalRule::new()
            .optimize(plan, &ConfigOptions::default())
            .unwrap()
    }

    #[test]
    fn round_robin_repartition_and_redundant_sort_are_removed() {
        // The shape EnforceDistribution + EnforceSorting leave behind when
        // parallelising an ordered scan: a round-robin repartition raising
        // the partition count and a sort repairing the ordering it destroyed.
        let repartition = Arc::new(
            RepartitionExec::try_new(
                non_overlapping_ordered_scan(),
                Partitioning::RoundRobinBatch(4),
            )
            .unwrap(),
        );
        let sort =
            Arc::new(SortExec::new(t_asc_ordering(), repartition).with_preserve_partitioning(true));
        let merge = Arc::new(SortPreservingMergeExec::new(t_asc_ordering(), sort));

        let optimized = optimize(merge);

        let progressive = (optimized.as_ref() as &dyn ExecutionPlan)
            .downcast_ref::<ProgressiveEvalExec>()
            .expect("expected ProgressiveEvalExec");
        assert!(
            (progressive.input().as_ref() as &dyn ExecutionPlan)
                .downcast_ref::<StatsExec>()
                .is_some(),
            "expected repartition and sort to be stripped from the input"
        );
    }

    #[test]
    fn sort_with_fetch_is_kept() {
        // A sort with a fetch limits its output; removing it would change
        // results, so it must survive even when the ordering is redundant.
        // Its statistics account for the fetch and become inexact, so the
        // whole optimization bails and the original plan is kept.
        let repartition = Arc::new(
            RepartitionExec::try_new(
                non_overlapping_ordered_scan(),
                Partitioning::RoundRobinBatch(4),
            )
            .unwrap(),
        );
        let sort = Arc::new(
            SortExec::new(t_asc_ordering(), repartition)
                .with_preserve_partitioning(true)
                .with_fetch(Some(5)),
        );
        let merge = Arc::new(SortPreservingMergeExec::new(t_asc_ordering(), sort));

        let optimized = optimize(merge);

        assert!(
            (optimized.as_ref() as &dyn ExecutionPlan)
                .downcast_ref::<SortPreservingMergeExec>()
                .is_some(),
            "expected the plan to be left unchanged"
        );
        assert_eq!(count_nodes::<SortExec>(&optimized), 1);
        assert_eq!(count_nodes::<RepartitionExec>(&optimized), 1);
    }

    #[test]
    fn hash_repartition_is_kept() {
        // Hash repartitions place rows deliberately; the rule must not touch
        // them, and without provable ordering the merge stays.
        let repartition = Arc::new(
            RepartitionExec::try_new(
                non_overlapping_ordered_scan(),
                Partitioning::Hash(vec![Arc::new(Column::new("t", 0))], 4),
            )
            .unwrap(),
        );
        let merge = Arc::new(SortPreservingMergeExec::new(t_asc_ordering(), repartition));

        let optimized = optimize(Arc::clone(&merge) as _);

        assert!(
            (optimized.as_ref() as &dyn ExecutionPlan)
                .downcast_ref::<SortPreservingMergeExec>()
                .is_some(),
            "expected the plan to be left unchanged"
        );
        assert_eq!(count_nodes::<RepartitionExec>(&optimized), 1);
    }

    #[test]
    fn repartition_is_kept_when_partitions_overlap() {
        // If the stripped plan still does not qualify for progressive
        // evaluation, the original plan (and its parallelism) is kept.
        let scan = StatsExec::with_ordering(
            vec![
                partition(vec![exact_i64(0, 150, 0), exact_i64(0, 10, 0)]),
                partition(vec![exact_i64(100, 200, 0), exact_i64(0, 10, 0)]),
            ],
            Some(t_asc_ordering()),
        );
        let repartition =
            Arc::new(RepartitionExec::try_new(scan, Partitioning::RoundRobinBatch(4)).unwrap());
        let merge = Arc::new(SortPreservingMergeExec::new(t_asc_ordering(), repartition));

        let optimized = optimize(merge);

        assert!(
            (optimized.as_ref() as &dyn ExecutionPlan)
                .downcast_ref::<SortPreservingMergeExec>()
                .is_some(),
            "expected the plan to be left unchanged"
        );
        assert_eq!(count_nodes::<RepartitionExec>(&optimized), 1);
    }

    fn count_nodes<T: ExecutionPlan>(plan: &Arc<dyn ExecutionPlan>) -> usize {
        let mut count = 0;
        plan.apply(|node| {
            if (node.as_ref() as &dyn ExecutionPlan)
                .downcast_ref::<T>()
                .is_some()
            {
                count += 1;
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .unwrap();
        count
    }
}
