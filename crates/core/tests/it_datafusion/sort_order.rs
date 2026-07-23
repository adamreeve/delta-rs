//! Tests for reading sorted Parquet data without a full sort (see plan.md).
//!
//! Step 1: verify the behaviour of plain DataFusion with a `ListingTable` over
//! Hive-partitioned parquet files, where each file is sorted by "timestamp",
//! files within a partition have non-overlapping timestamp ranges, and the
//! parquet `sorting_columns` metadata is set. This establishes the expected
//! plan shapes that the Delta table provider should later reproduce.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use arrow_array::cast::AsArray;
use arrow_array::types::{Int64Type, TimestampMicrosecondType};
use arrow_array::{Int64Array, RecordBatch, StringArray, TimestampMicrosecondArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::datasource::file_format::parquet::ParquetFormat;
use datafusion::datasource::listing::ListingOptions;
use datafusion::physical_plan::displayable;
use datafusion::prelude::{SessionConfig, SessionContext, col};
use deltalake_core::DeltaTable;
use deltalake_core::delta_datafusion::{FileSortColumn, create_session};
use deltalake_core::kernel::{DataType as DeltaDataType, PrimitiveType, StructField};
use deltalake_core::protocol::SaveMode;
use deltalake_test::TestResult;
use parquet::arrow::ArrowWriter;
use parquet::file::metadata::SortingColumn;
use parquet::file::properties::WriterProperties;
use tempfile::TempDir;

fn file_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new(
            "timestamp",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        ),
        Field::new("value", DataType::Int64, false),
    ]))
}

/// Writer properties declaring the file is sorted by its first column
/// (timestamp) ascending.
fn timestamp_sorting_properties() -> WriterProperties {
    WriterProperties::builder()
        .set_sorting_columns(Some(vec![SortingColumn {
            column_idx: 0,
            descending: false,
            nulls_first: false,
        }]))
        .build()
}

/// Write a parquet file containing `len` rows with timestamps starting at
/// `start` seconds, ordered ascending, with `sorting_columns` metadata set.
fn write_sorted_file(path: &Path, start: i64, len: i64) -> TestResult<()> {
    let timestamps: Vec<i64> = (start..start + len).map(|s| s * 1_000_000).collect();
    let values: Vec<i64> = (start..start + len).collect();
    let batch = RecordBatch::try_new(
        file_schema(),
        vec![
            Arc::new(TimestampMicrosecondArray::from(timestamps)),
            Arc::new(Int64Array::from(values)),
        ],
    )?;

    let props = timestamp_sorting_properties();
    let mut writer = ArrowWriter::try_new(File::create(path)?, file_schema(), Some(props))?;
    writer.write(&batch)?;
    writer.close()?;
    Ok(())
}

/// Create a Hive-partitioned parquet table where each file is sorted by
/// timestamp and files within a partition have non-overlapping timestamp
/// ranges, while files in different partitions overlap. The file count is
/// uneven across partitions so that the default file grouping (which ignores
/// statistics) always places overlapping files in the same group, requiring a
/// full sort unless the groups are formed from statistics.
fn write_partitioned_table(root: &Path) -> TestResult<()> {
    // part=A covers [0, 300), part=B covers [50, 150)
    let files = [
        ("part=A", "0.parquet", 0, 100),
        ("part=A", "1.parquet", 100, 100),
        ("part=A", "2.parquet", 200, 100),
        ("part=B", "0.parquet", 50, 100),
    ];
    for (partition, name, start, len) in files {
        let dir = root.join(partition);
        std::fs::create_dir_all(&dir)?;
        write_sorted_file(&dir.join(name), start, len)?;
    }
    Ok(())
}

struct ListingFlags {
    split_file_groups_by_statistics: bool,
    enable_sort_pushdown: bool,
    /// Declare the sort order on the listing table; when false we rely on
    /// inference from the parquet `sorting_columns` metadata.
    declare_file_sort_order: bool,
}

/// Register a `ListingTable` over the partitioned parquet data and return the
/// rendered physical plan and results for `ORDER BY timestamp`.
async fn plan_sorted_query(
    root: &Path,
    flags: ListingFlags,
) -> TestResult<(String, Vec<RecordBatch>)> {
    let mut config = SessionConfig::new()
        // fewer target partitions than files so file groups hold multiple files
        .with_target_partitions(2)
        .with_collect_statistics(true);
    config
        .options_mut()
        .execution
        .split_file_groups_by_statistics = flags.split_file_groups_by_statistics;
    config.options_mut().optimizer.enable_sort_pushdown = flags.enable_sort_pushdown;
    let ctx = SessionContext::new_with_config(config);

    let mut listing_options = ListingOptions::new(Arc::new(ParquetFormat::default()))
        // pick up target_partitions and collect_statistics from the session;
        // ListingOptions::new defaults to one partition and no statistics
        .with_session_config_options(&ctx.copied_config())
        .with_table_partition_cols(vec![("part".to_string(), DataType::Utf8)]);
    if flags.declare_file_sort_order {
        listing_options =
            listing_options.with_file_sort_order(vec![vec![col("timestamp").sort(true, false)]]);
    }

    ctx.register_listing_table(
        "test_table",
        format!("{}/", root.display()),
        listing_options,
        Some(file_schema()),
        None,
    )
    .await?;

    let df = ctx
        .sql("SELECT \"timestamp\", value, part FROM test_table ORDER BY \"timestamp\"")
        .await?;
    let plan = df.create_physical_plan().await?;
    let rendered = displayable(plan.as_ref()).indent(true).to_string();
    let batches = datafusion::physical_plan::collect(plan, ctx.task_ctx()).await?;
    Ok((rendered, batches))
}

/// Check the query returned all 400 rows in timestamp order.
fn assert_sorted_result(batches: &[RecordBatch]) {
    let timestamps: Vec<i64> = batches
        .iter()
        .flat_map(|batch| {
            batch
                .column(0)
                .as_primitive::<TimestampMicrosecondType>()
                .values()
                .iter()
                .copied()
        })
        .collect();
    assert_eq!(timestamps.len(), 400);
    assert!(
        timestamps.windows(2).all(|pair| pair[0] <= pair[1]),
        "results are not sorted by timestamp"
    );
}

/// With `split_file_groups_by_statistics` enabled and a declared file sort
/// order, the sorted files should be regrouped into non-overlapping file
/// groups and merged with a `SortPreservingMergeExec` — no `SortExec`.
#[tokio::test]
async fn listing_table_split_by_statistics_avoids_sort() -> TestResult<()> {
    let dir = TempDir::new()?;
    write_partitioned_table(dir.path())?;

    let (plan, batches) = plan_sorted_query(
        dir.path(),
        ListingFlags {
            split_file_groups_by_statistics: true,
            enable_sort_pushdown: false,
            declare_file_sort_order: true,
        },
    )
    .await?;

    assert!(
        !plan.contains("SortExec"),
        "expected no SortExec in plan:\n{plan}"
    );
    assert!(
        plan.contains("SortPreservingMergeExec"),
        "expected SortPreservingMergeExec in plan:\n{plan}"
    );
    assert_sorted_result(&batches);
    Ok(())
}

/// Without `split_file_groups_by_statistics` or sort pushdown, a full sort is
/// required even though the sort order is declared, because the default file
/// groups interleave files with overlapping timestamp ranges.
#[tokio::test]
async fn listing_table_without_optimizations_requires_sort() -> TestResult<()> {
    let dir = TempDir::new()?;
    write_partitioned_table(dir.path())?;

    let (plan, batches) = plan_sorted_query(
        dir.path(),
        ListingFlags {
            split_file_groups_by_statistics: false,
            enable_sort_pushdown: false,
            declare_file_sort_order: true,
        },
    )
    .await?;

    assert!(
        plan.contains("SortExec"),
        "expected SortExec in plan:\n{plan}"
    );
    assert_sorted_result(&batches);
    Ok(())
}

/// With the `PushdownSort` optimizer rule enabled (the default) the source can
/// reorder files by statistics at optimization time, avoiding the sort even
/// when `split_file_groups_by_statistics` is disabled.
#[tokio::test]
async fn listing_table_sort_pushdown_avoids_sort() -> TestResult<()> {
    let dir = TempDir::new()?;
    write_partitioned_table(dir.path())?;

    let (plan, batches) = plan_sorted_query(
        dir.path(),
        ListingFlags {
            split_file_groups_by_statistics: false,
            enable_sort_pushdown: true,
            declare_file_sort_order: true,
        },
    )
    .await?;

    assert!(
        !plan.contains("SortExec"),
        "expected no SortExec in plan:\n{plan}"
    );
    assert_sorted_result(&batches);
    Ok(())
}

// --- Step 2: end-to-end Delta table test (see plan.md) ---

fn delta_write_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new(
            "timestamp",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        ),
        Field::new("value", DataType::Int64, false),
        Field::new("part", DataType::Utf8, false),
    ]))
}

fn delta_write_batch(part: &str, start: i64, len: i64) -> TestResult<RecordBatch> {
    let timestamps: Vec<i64> = (start..start + len).map(|s| s * 1_000_000).collect();
    let values: Vec<i64> = (start..start + len).collect();
    let parts: Vec<&str> = (0..len).map(|_| part).collect();
    Ok(RecordBatch::try_new(
        delta_write_schema(),
        vec![
            Arc::new(TimestampMicrosecondArray::from(timestamps)),
            Arc::new(Int64Array::from(values)),
            Arc::new(StringArray::from(parts)),
        ],
    )?)
}

/// Create a Delta table partitioned by "part" with the same data layout as
/// [`write_partitioned_table`]: every file sorted by timestamp with
/// `sorting_columns` metadata set, non-overlapping timestamp ranges within a
/// partition, overlapping ranges across partitions.
async fn sorted_delta_table() -> TestResult<DeltaTable> {
    let mut table = DeltaTable::new_in_memory()
        .create()
        .with_columns(vec![
            StructField::new(
                "timestamp".to_string(),
                DeltaDataType::Primitive(PrimitiveType::TimestampNtz),
                false,
            ),
            StructField::new(
                "value".to_string(),
                DeltaDataType::Primitive(PrimitiveType::Long),
                false,
            ),
            StructField::new(
                "part".to_string(),
                DeltaDataType::Primitive(PrimitiveType::String),
                false,
            ),
        ])
        .with_partition_columns(vec!["part"])
        .await?;

    let writes = [
        ("A", 0, 100),
        ("A", 100, 100),
        ("A", 200, 100),
        ("B", 50, 100),
    ];
    for (part, start, len) in writes {
        table = table
            .write(vec![delta_write_batch(part, start, len)?])
            .with_save_mode(SaveMode::Append)
            .with_writer_properties(timestamp_sorting_properties())
            .await?;
    }
    assert_eq!(table.snapshot()?.log_data().num_files(), 4);
    Ok(table)
}

/// Querying a Delta table whose files are sorted by timestamp, with that
/// order declared on the table provider, should use the sort pushdown
/// optimization and avoid a full sort.
#[tokio::test]
async fn delta_table_sorted_scan_avoids_sort() -> TestResult<()> {
    let table = sorted_delta_table().await?;

    let ctx = create_session().into_inner();
    let provider = table
        .table_provider()
        .with_file_sort_order([FileSortColumn::asc("timestamp")])
        .await?;
    ctx.register_table("test_table", provider)?;

    let df = ctx
        .sql("SELECT \"timestamp\", value, part FROM test_table ORDER BY \"timestamp\"")
        .await?;
    let plan = df.create_physical_plan().await?;
    let rendered = displayable(plan.as_ref()).indent(true).to_string();
    let batches = datafusion::physical_plan::collect(plan, ctx.task_ctx()).await?;

    assert_sorted_result(&batches);
    assert!(
        !rendered.contains("SortExec"),
        "expected no SortExec in plan:\n{rendered}"
    );
    assert!(
        rendered.contains("SortPreservingMergeExec"),
        "expected SortPreservingMergeExec in plan:\n{rendered}"
    );
    Ok(())
}

/// With no declared sort order, the file sort order is inferred from the
/// parquet `sorting_columns` metadata written by
/// [`timestamp_sorting_properties`], and the full sort is avoided.
#[tokio::test]
async fn delta_table_inferred_sort_order_avoids_sort() -> TestResult<()> {
    let table = sorted_delta_table().await?;

    let ctx = create_session().into_inner();
    let provider = table
        .table_provider()
        .with_inferred_file_sort_order(true)
        .await?;
    ctx.register_table("test_table", provider)?;

    let df = ctx
        .sql("SELECT \"timestamp\", value, part FROM test_table ORDER BY \"timestamp\"")
        .await?;
    let plan = df.create_physical_plan().await?;
    let rendered = displayable(plan.as_ref()).indent(true).to_string();
    let batches = datafusion::physical_plan::collect(plan, ctx.task_ctx()).await?;

    assert_sorted_result(&batches);
    assert!(
        !rendered.contains("SortExec"),
        "expected no SortExec in plan:\n{rendered}"
    );
    assert!(
        rendered.contains("SortPreservingMergeExec"),
        "expected SortPreservingMergeExec in plan:\n{rendered}"
    );
    Ok(())
}

/// Inference is harmless when the files carry no `sorting_columns` metadata:
/// the query falls back to a full sort with correct results.
#[tokio::test]
async fn delta_table_inferred_sort_order_without_metadata() -> TestResult<()> {
    let mut table = DeltaTable::new_in_memory()
        .create()
        .with_columns(vec![
            StructField::new(
                "timestamp".to_string(),
                DeltaDataType::Primitive(PrimitiveType::TimestampNtz),
                false,
            ),
            StructField::new(
                "value".to_string(),
                DeltaDataType::Primitive(PrimitiveType::Long),
                false,
            ),
            StructField::new(
                "part".to_string(),
                DeltaDataType::Primitive(PrimitiveType::String),
                false,
            ),
        ])
        .with_partition_columns(vec!["part"])
        .await?;
    for (part, start, len) in [("A", 0, 100), ("A", 100, 100), ("B", 50, 100)] {
        table = table
            .write(vec![delta_write_batch(part, start, len)?])
            .with_save_mode(SaveMode::Append)
            .await?;
    }

    let ctx = create_session().into_inner();
    let provider = table
        .table_provider()
        .with_inferred_file_sort_order(true)
        .await?;
    ctx.register_table("test_table", provider)?;

    let df = ctx
        .sql("SELECT \"timestamp\", value, part FROM test_table ORDER BY \"timestamp\"")
        .await?;
    let plan = df.create_physical_plan().await?;
    let rendered = displayable(plan.as_ref()).indent(true).to_string();
    let batches = datafusion::physical_plan::collect(plan, ctx.task_ctx()).await?;

    assert!(
        rendered.contains("SortExec"),
        "expected SortExec in plan:\n{rendered}"
    );
    let timestamps: Vec<i64> = batches
        .iter()
        .flat_map(|batch| {
            batch
                .column(0)
                .as_primitive::<TimestampMicrosecondType>()
                .values()
                .iter()
                .copied()
        })
        .collect();
    assert_eq!(timestamps.len(), 300);
    assert!(timestamps.windows(2).all(|pair| pair[0] <= pair[1]));
    Ok(())
}

/// When the query does not scan the declared sort column, the declared order
/// cannot be exposed and the query falls back to a full sort with correct
/// results.
#[tokio::test]
async fn delta_table_sort_order_degrades_without_sort_column() -> TestResult<()> {
    let table = sorted_delta_table().await?;

    let ctx = create_session().into_inner();
    let provider = table
        .table_provider()
        .with_file_sort_order([FileSortColumn::asc("timestamp")])
        .await?;
    ctx.register_table("test_table", provider)?;

    let df = ctx
        .sql("SELECT value FROM test_table ORDER BY value")
        .await?;
    let plan = df.create_physical_plan().await?;
    let rendered = displayable(plan.as_ref()).indent(true).to_string();
    let batches = datafusion::physical_plan::collect(plan, ctx.task_ctx()).await?;

    assert!(
        rendered.contains("SortExec"),
        "expected SortExec in plan:\n{rendered}"
    );
    let values: Vec<i64> = batches
        .iter()
        .flat_map(|batch| batch.column(0).as_primitive::<Int64Type>().values().iter())
        .copied()
        .collect();
    assert_eq!(values.len(), 400);
    assert!(values.windows(2).all(|pair| pair[0] <= pair[1]));
    Ok(())
}

/// Declaring a sort order on a partition column or an unknown column is
/// rejected when building the provider.
#[tokio::test]
async fn delta_table_sort_order_validation() -> TestResult<()> {
    let table = sorted_delta_table().await?;

    let err = table
        .table_provider()
        .with_file_sort_order([FileSortColumn::asc("part")])
        .await
        .expect_err("partition column sort order should be rejected");
    assert!(err.to_string().contains("partition column"), "{err}");

    let err = table
        .table_provider()
        .with_file_sort_order([FileSortColumn::asc("missing")])
        .await
        .expect_err("unknown column sort order should be rejected");
    assert!(err.to_string().contains("does not exist"), "{err}");
    Ok(())
}

// --- ProgressiveEval: ordered reads over non-overlapping but
// --- internally-unsorted files (see progressive_eval.md) ---

fn unsorted_schema(nullable_timestamp: bool) -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new(
            "timestamp",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            nullable_timestamp,
        ),
        Field::new("value", DataType::Int64, false),
    ]))
}

/// One file's batch: `len` unique timestamps starting at `start` seconds, in a
/// deterministic shuffled (non-sorted) order; `value` mirrors the timestamp
/// second so full rows can be compared across plans.
fn unsorted_batch(start: i64, len: i64, nulls: usize) -> TestResult<RecordBatch> {
    // Deterministic shuffle: stride through the range with a step coprime to
    // its length so every element is visited once, in non-monotonic order.
    let step = (0..).map(|i| len / 2 + 1 + i).find(|s| gcd(*s, len) == 1);
    let step = step.expect("a coprime step exists");
    let seconds: Vec<i64> = (0..len).map(|i| start + (i * step) % len).collect();
    let timestamps: Vec<Option<i64>> = seconds
        .iter()
        .enumerate()
        .map(|(i, s)| (i >= nulls).then_some(s * 1_000_000))
        .collect();
    let values: Vec<i64> = seconds.clone();
    Ok(RecordBatch::try_new(
        unsorted_schema(nulls > 0),
        vec![
            Arc::new(TimestampMicrosecondArray::from(timestamps)),
            Arc::new(Int64Array::from(values)),
        ],
    )?)
}

fn gcd(a: i64, b: i64) -> i64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// Create a non-partitioned Delta table with one file per `(start, len)`
/// range. Rows within each file are deliberately NOT sorted by timestamp, so
/// the within-file sort order cannot be declared or inferred; only per-file
/// min/max statistics relate the files to each other.
async fn unsorted_delta_table(
    files: &[(i64, i64)],
    nulls_in_file: Option<usize>,
) -> TestResult<DeltaTable> {
    let nullable = nulls_in_file.is_some();
    let mut table = DeltaTable::new_in_memory()
        .create()
        .with_columns(vec![
            StructField::new(
                "timestamp".to_string(),
                DeltaDataType::Primitive(PrimitiveType::TimestampNtz),
                nullable,
            ),
            StructField::new(
                "value".to_string(),
                DeltaDataType::Primitive(PrimitiveType::Long),
                false,
            ),
        ])
        .await?;

    for (index, (start, len)) in files.iter().enumerate() {
        let nulls = (nulls_in_file == Some(index)) as usize;
        table = table
            .write(vec![unsorted_batch(*start, *len, nulls)?])
            .with_save_mode(SaveMode::Append)
            .await?;
    }
    assert_eq!(table.snapshot()?.log_data().num_files(), files.len());
    Ok(table)
}

/// Render the plan and collect the results of `query` against `table`,
/// optionally materializing per-file stats for the timestamp column.
async fn plan_unsorted_query(
    table: &DeltaTable,
    with_stats_columns: bool,
    query: &str,
) -> TestResult<(String, Vec<RecordBatch>)> {
    let ctx = create_session().into_inner();
    let mut builder = table.table_provider();
    if with_stats_columns {
        builder = builder.with_stats_columns(["timestamp"]);
    }
    ctx.register_table("test_table", builder.await?)?;

    let df = ctx.sql(query).await?;
    let plan = df.create_physical_plan().await?;
    let rendered = displayable(plan.as_ref()).indent(true).to_string();
    let batches = datafusion::physical_plan::collect(plan, ctx.task_ctx()).await?;
    Ok((rendered, batches))
}

fn collected_timestamps(batches: &[RecordBatch]) -> Vec<i64> {
    batches
        .iter()
        .flat_map(|batch| {
            batch
                .column(0)
                .as_primitive::<TimestampMicrosecondType>()
                .values()
                .iter()
                .copied()
        })
        .collect()
}

/// Files with non-overlapping timestamp ranges but unsorted rows within each
/// file: the scan is rebuilt with one file group per range batch, each batch
/// is sorted separately, and `ProgressiveEvalExec` streams the sorted batches
/// in turn — no global sort over the whole dataset.
#[tokio::test]
async fn delta_table_unsorted_disjoint_files_uses_progressive_eval() -> TestResult<()> {
    let table = unsorted_delta_table(&[(0, 100), (100, 100), (200, 100), (300, 100)], None).await?;

    let (rendered, batches) = plan_unsorted_query(
        &table,
        true,
        "SELECT \"timestamp\", value FROM test_table ORDER BY \"timestamp\"",
    )
    .await?;

    assert!(
        rendered.contains("ProgressiveEvalExec"),
        "expected ProgressiveEvalExec in plan:\n{rendered}"
    );
    assert!(
        rendered.contains("input_ranges="),
        "expected input_ranges in plan:\n{rendered}"
    );
    // The per-batch SortExec must sit below the ProgressiveEvalExec; there
    // must be no SortExec above it (which would be a global sort).
    let progressive_pos = rendered.find("ProgressiveEvalExec").unwrap();
    let sort_pos = rendered.find("SortExec").expect("per-batch SortExec");
    assert!(
        progressive_pos < sort_pos,
        "expected the SortExec below ProgressiveEvalExec:\n{rendered}"
    );

    let timestamps = collected_timestamps(&batches);
    assert_eq!(timestamps.len(), 400);
    assert!(
        timestamps.windows(2).all(|pair| pair[0] <= pair[1]),
        "results are not sorted by timestamp"
    );
    Ok(())
}

/// Without materialized stats for the sort column the batching cannot prove
/// non-overlap, so the global sort is kept — and still returns sorted data.
#[tokio::test]
async fn delta_table_unsorted_files_without_stats_columns_keeps_global_sort() -> TestResult<()> {
    let table = unsorted_delta_table(&[(0, 100), (100, 100), (200, 100), (300, 100)], None).await?;

    let (rendered, batches) = plan_unsorted_query(
        &table,
        false,
        "SELECT \"timestamp\", value FROM test_table ORDER BY \"timestamp\"",
    )
    .await?;

    assert!(
        !rendered.contains("ProgressiveEvalExec"),
        "expected no ProgressiveEvalExec in plan:\n{rendered}"
    );
    assert!(
        rendered.contains("SortExec"),
        "expected SortExec in plan:\n{rendered}"
    );
    let timestamps = collected_timestamps(&batches);
    assert_eq!(timestamps.len(), 400);
    assert!(timestamps.windows(2).all(|pair| pair[0] <= pair[1]));
    Ok(())
}

/// When every file overlaps every other file the sweep collapses to a single
/// batch, which is no better than a global sort, so the plan falls back.
#[tokio::test]
async fn delta_table_unsorted_overlapping_files_keeps_global_sort() -> TestResult<()> {
    let table = unsorted_delta_table(&[(0, 100), (50, 100), (25, 100), (75, 100)], None).await?;

    let (rendered, batches) = plan_unsorted_query(
        &table,
        true,
        "SELECT \"timestamp\", value FROM test_table ORDER BY \"timestamp\"",
    )
    .await?;

    assert!(
        !rendered.contains("ProgressiveEvalExec"),
        "expected no ProgressiveEvalExec in plan:\n{rendered}"
    );
    assert!(
        rendered.contains("SortExec"),
        "expected SortExec in plan:\n{rendered}"
    );
    let timestamps = collected_timestamps(&batches);
    assert_eq!(timestamps.len(), 400);
    assert!(timestamps.windows(2).all(|pair| pair[0] <= pair[1]));
    Ok(())
}

/// NULLs in the sort column break the concatenation argument (NULLS
/// FIRST/LAST placement is per sorted batch, not global), so any file with a
/// nonzero null count disables the optimization.
#[tokio::test]
async fn delta_table_nulls_in_sort_column_keep_global_sort() -> TestResult<()> {
    let table =
        unsorted_delta_table(&[(0, 100), (100, 100), (200, 100), (300, 100)], Some(2)).await?;

    let (rendered, batches) = plan_unsorted_query(
        &table,
        true,
        "SELECT \"timestamp\", value FROM test_table ORDER BY \"timestamp\"",
    )
    .await?;

    assert!(
        !rendered.contains("ProgressiveEvalExec"),
        "expected no ProgressiveEvalExec in plan:\n{rendered}"
    );
    assert!(
        rendered.contains("SortExec"),
        "expected SortExec in plan:\n{rendered}"
    );
    let row_count: usize = batches.iter().map(|batch| batch.num_rows()).sum();
    assert_eq!(row_count, 400);
    Ok(())
}

/// `ORDER BY ... LIMIT n`: the `PushdownSort` rule forwards the eliminated
/// `SortExec`'s fetch to the `ProgressiveEvalExec`, which stops after the
/// first batch covers the limit — later batches are never executed (only the
/// polled stream plus one prefetched stream are started).
#[tokio::test]
async fn delta_table_progressive_eval_limit_early_termination() -> TestResult<()> {
    use datafusion::physical_plan::{ExecutionPlan, ExecutionPlanVisitor, accept};

    let table = unsorted_delta_table(&[(0, 100), (100, 100), (200, 100), (300, 100)], None).await?;

    let ctx = create_session().into_inner();
    let provider = table
        .table_provider()
        .with_stats_columns(["timestamp"])
        .await?;
    ctx.register_table("test_table", provider)?;

    let df = ctx
        .sql("SELECT \"timestamp\", value FROM test_table ORDER BY \"timestamp\" LIMIT 50")
        .await?;
    let plan = df.create_physical_plan().await?;
    let rendered = displayable(plan.as_ref()).indent(true).to_string();
    assert!(
        rendered.contains("ProgressiveEvalExec: fetch=50"),
        "expected ProgressiveEvalExec with forwarded fetch in plan:\n{rendered}"
    );

    let batches = datafusion::physical_plan::collect(plan.clone(), ctx.task_ctx()).await?;
    let timestamps = collected_timestamps(&batches);
    assert_eq!(timestamps.len(), 50);
    assert_eq!(
        timestamps,
        (0..50).map(|s| s * 1_000_000).collect::<Vec<_>>()
    );

    // Laziness: with 4 range batches and the limit covered by the first one,
    // only the first stream (plus one prefetched stream) may have been
    // executed. Later batches' files are never opened.
    #[derive(Default)]
    struct ProgressiveEvalMetrics {
        num_inputs: Option<usize>,
        num_read_inputs: Option<usize>,
    }
    impl ExecutionPlanVisitor for ProgressiveEvalMetrics {
        type Error = datafusion::error::DataFusionError;
        fn pre_visit(&mut self, plan: &dyn ExecutionPlan) -> Result<bool, Self::Error> {
            if plan.name() == "ProgressiveEvalExec" {
                let metrics = plan.metrics().expect("metrics recorded after execution");
                self.num_inputs = metrics.sum_by_name("num_inputs").map(|m| m.as_usize());
                self.num_read_inputs = metrics.sum_by_name("num_read_inputs").map(|m| m.as_usize());
                return Ok(false);
            }
            Ok(true)
        }
    }
    let mut visitor = ProgressiveEvalMetrics::default();
    accept(plan.as_ref(), &mut visitor)?;
    assert_eq!(visitor.num_inputs, Some(4), "expected 4 range batches");
    assert_eq!(
        visitor.num_read_inputs,
        Some(2),
        "expected only the first batch plus one prefetched batch to execute"
    );
    Ok(())
}

/// Correctness across overlap patterns, with and without LIMIT: the
/// range-batched plan must return exactly what the global-sort plan returns.
#[tokio::test]
async fn delta_table_range_batching_matches_global_sort() -> TestResult<()> {
    // (name, per-file (start, len)); files are 40 rows each.
    let patterns: &[(&str, &[(i64, i64)])] = &[
        ("disjoint", &[(0, 40), (40, 40), (120, 40), (80, 40)]),
        ("touching", &[(0, 41), (40, 41), (80, 41), (120, 41)]),
        ("partial_overlap", &[(0, 40), (30, 40), (90, 40), (60, 40)]),
        ("full_overlap", &[(0, 40), (0, 40), (0, 40), (0, 40)]),
        ("contained", &[(0, 160), (10, 20), (50, 20), (100, 20)]),
        ("two_batches", &[(0, 40), (20, 40), (100, 40), (120, 40)]),
    ];

    for (name, files) in patterns {
        let table = unsorted_delta_table(files, None).await?;
        for query in [
            "SELECT \"timestamp\", value FROM test_table ORDER BY \"timestamp\"",
            "SELECT \"timestamp\", value FROM test_table ORDER BY \"timestamp\" LIMIT 25",
        ] {
            let (_, optimized) = plan_unsorted_query(&table, true, query).await?;
            let (baseline_plan, baseline) = plan_unsorted_query(&table, false, query).await?;
            assert!(
                !baseline_plan.contains("ProgressiveEvalExec"),
                "baseline must not use ProgressiveEvalExec ({name}):\n{baseline_plan}"
            );

            let optimized_ts = collected_timestamps(&optimized);
            let baseline_ts = collected_timestamps(&baseline);
            assert_eq!(
                optimized_ts, baseline_ts,
                "timestamps diverge for pattern '{name}' with query '{query}'"
            );
            assert!(
                optimized_ts.windows(2).all(|pair| pair[0] <= pair[1]),
                "unsorted result for pattern '{name}'"
            );

            // Rows may tie on timestamp across overlapping files; compare the
            // full (timestamp, value) multiset instead of row order.
            let pairs = |batches: &[RecordBatch]| {
                let mut pairs: Vec<(i64, i64)> = batches
                    .iter()
                    .flat_map(|batch| {
                        let ts = batch.column(0).as_primitive::<TimestampMicrosecondType>();
                        let values = batch.column(1).as_primitive::<Int64Type>();
                        ts.values()
                            .iter()
                            .zip(values.values().iter())
                            .map(|(t, v)| (*t, *v))
                            .collect::<Vec<_>>()
                    })
                    .collect();
                pairs.sort_unstable();
                pairs
            };
            if !query.contains("LIMIT") {
                assert_eq!(
                    pairs(&optimized),
                    pairs(&baseline),
                    "row multiset diverges for pattern '{name}'"
                );
            }
        }
    }
    Ok(())
}

/// With no declared sort order, the table's ordering is inferred from the
/// parquet `sorting_columns` metadata written to each file.
#[tokio::test]
async fn listing_table_infers_order_from_sorting_columns() -> TestResult<()> {
    let dir = TempDir::new()?;
    write_partitioned_table(dir.path())?;

    let (plan, batches) = plan_sorted_query(
        dir.path(),
        ListingFlags {
            split_file_groups_by_statistics: true,
            enable_sort_pushdown: false,
            declare_file_sort_order: false,
        },
    )
    .await?;

    assert!(
        !plan.contains("SortExec"),
        "expected no SortExec in plan:\n{plan}"
    );
    assert_sorted_result(&batches);
    Ok(())
}
