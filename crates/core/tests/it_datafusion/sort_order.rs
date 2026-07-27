//! End-to-end tests of the Delta table provider with a per-file sort order
//! declared via `with_file_sort_order`.

use std::sync::Arc;

use arrow_array::cast::AsArray;
use arrow_array::types::{Int64Type, TimestampMicrosecondType};
use arrow_array::{Int64Array, RecordBatch, StringArray, TimestampMicrosecondArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::physical_plan::displayable;
use deltalake_core::DeltaTable;
use deltalake_core::delta_datafusion::{FileSortColumn, create_session};
use deltalake_core::kernel::{DataType as DeltaDataType, PrimitiveType, StructField};
use deltalake_core::protocol::SaveMode;
use deltalake_test::TestResult;

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

/// Create a Delta table partitioned by "part": every file sorted by
/// timestamp, non-overlapping timestamp ranges within a partition,
/// overlapping ranges across partitions. The file count is uneven across
/// partitions so that grouping which ignores statistics always places
/// overlapping files in the same group.
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

/// Create a Delta table whose files are all sorted by timestamp with fully
/// non-overlapping ranges (single partition value), appended out of timestamp
/// order so that the default file listing is not already min-sorted.
async fn disjoint_delta_table() -> TestResult<DeltaTable> {
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

    for start in [200, 0, 300, 100] {
        table = table
            .write(vec![delta_write_batch("A", start, 100)?])
            .with_save_mode(SaveMode::Append)
            .await?;
    }
    assert_eq!(table.snapshot()?.log_data().num_files(), 4);
    Ok(table)
}

/// Plan and run `ORDER BY timestamp` against a provider with the file sort
/// order declared but statistics-based file grouping disabled, with the
/// `PushdownSort` optimizer rule toggled on or off.
async fn plan_ungrouped_sorted_query(
    table: &DeltaTable,
    enable_sort_pushdown: bool,
) -> TestResult<(String, Vec<RecordBatch>)> {
    let ctx = create_session().into_inner();
    ctx.sql(&format!(
        "SET datafusion.optimizer.enable_sort_pushdown = {enable_sort_pushdown}"
    ))
    .await?
    .collect()
    .await?;
    let provider = table
        .table_provider()
        .with_file_sort_order([FileSortColumn::asc("timestamp")])
        .with_file_sort_order_grouping(false)
        .await?;
    ctx.register_table("test_table", provider)?;

    let df = ctx
        .sql("SELECT \"timestamp\", value, part FROM test_table ORDER BY \"timestamp\"")
        .await?;
    let plan = df.create_physical_plan().await?;
    let rendered = displayable(plan.as_ref()).indent(true).to_string();
    let batches = datafusion::physical_plan::collect(plan, ctx.task_ctx()).await?;
    Ok((rendered, batches))
}

/// With statistics-based file grouping disabled, the declared ordering does
/// not validate at planning time (the files are listed out of min/max order),
/// so a `SortExec` is planned; DataFusion's sort-pushdown optimizer rule then
/// reorders the files by statistics, restores the declared ordering, and
/// eliminates the sort.
#[tokio::test]
async fn delta_table_sort_order_pushdown_avoids_sort() -> TestResult<()> {
    let table = disjoint_delta_table().await?;

    // Without the optimizer rule the query needs a full sort: the declared
    // ordering alone is not enough while the file listing is unordered.
    let (plan, batches) = plan_ungrouped_sorted_query(&table, false).await?;
    assert!(
        plan.contains("SortExec"),
        "expected SortExec in plan without the pushdown rule:\n{plan}"
    );
    assert_sorted_result(&batches);

    // With the rule, `try_pushdown_sort` reorders the disjoint files by their
    // statistics and reports an exact ordering, so the sort is eliminated.
    let (plan, batches) = plan_ungrouped_sorted_query(&table, true).await?;
    assert!(
        !plan.contains("SortExec"),
        "expected the pushdown rule to eliminate the SortExec:\n{plan}"
    );
    assert_sorted_result(&batches);
    Ok(())
}

/// Without statistics-based grouping, the sort pushdown can only reorder files
/// within the existing groups; when files overlap it cannot claim an exact
/// ordering and the full sort is kept, with correct results.
#[tokio::test]
async fn delta_table_sort_order_pushdown_keeps_sort_when_files_overlap() -> TestResult<()> {
    let table = sorted_delta_table().await?;

    let ctx = create_session().into_inner();
    let provider = table
        .table_provider()
        .with_file_sort_order([FileSortColumn::asc("timestamp")])
        .with_file_sort_order_grouping(false)
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
    assert_sorted_result(&batches);
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

