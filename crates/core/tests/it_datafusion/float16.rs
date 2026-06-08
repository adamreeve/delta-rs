// Test basic operations on a table that uses the float16 (half-precision) feature.

use arrow_array::cast::AsArray;
use arrow_array::types::Float16Type;
use arrow_array::{Float16Array, RecordBatch};
use arrow_schema::{DataType, Field, Schema};
use datafusion::prelude::SessionContext;
use deltalake_core::delta_datafusion::create_session;
use deltalake_core::{DeltaResult, DeltaTable};
use half::f16;
use std::sync::Arc;

fn float16_array(values: Vec<f32>) -> Arc<Float16Array> {
    Arc::new(Float16Array::from(
        values.into_iter().map(f16::from_f32).collect::<Vec<_>>(),
    ))
}

async fn setup_table() -> DeltaResult<(DeltaTable, Arc<Schema>)> {
    let arrow_schema = Arc::new(Schema::new(vec![Field::new("x", DataType::Float16, true)]));

    let batch = RecordBatch::try_new(
        arrow_schema.clone(),
        vec![float16_array(vec![1.0, 2.5, 4.0])],
    )?;

    let table: DeltaTable = DeltaTable::new_in_memory().write(vec![batch]).await?;

    Ok((table, arrow_schema))
}

async fn get_data(table: DeltaTable) -> Vec<RecordBatch> {
    let ctx: SessionContext = create_session().into();
    table.update_datafusion_session(&ctx.state()).unwrap();
    ctx.register_table("test", table.table_provider().await.unwrap())
        .unwrap();
    ctx.sql("select * from test")
        .await
        .unwrap()
        .collect()
        .await
        .unwrap()
}

/// Collect the float16 `x` column from a set of batches as `f32` values, sorted ascending.
fn sorted_values(batches: Vec<RecordBatch>) -> Vec<f32> {
    let mut values: Vec<f32> = Vec::new();
    for batch in batches {
        let float_column = batch.column(0).as_primitive::<Float16Type>();
        for i in 0..batch.num_rows() {
            values.push(float_column.value(i).to_f32());
        }
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    values
}

#[tokio::test]
async fn read_float16_table() -> DeltaResult<()> {
    let (table, _) = setup_table().await?;
    let batches = get_data(table).await;

    let schema = batches[0].schema();
    let float_field = schema.field_with_name("x")?;
    assert_eq!(float_field.data_type(), &DataType::Float16);

    assert_eq!(sorted_values(batches), vec![1.0, 2.5, 4.0]);

    Ok(())
}

#[tokio::test]
async fn append_float16() -> DeltaResult<()> {
    let (table, arrow_schema) = setup_table().await?;

    let new_batch =
        RecordBatch::try_new(arrow_schema.clone(), vec![float16_array(vec![8.0, 16.0])])?;
    let table = table.write(vec![new_batch]).await?;
    assert_eq!(table.version(), Some(1));

    let batches = get_data(table).await;
    assert_eq!(sorted_values(batches), vec![1.0, 2.5, 4.0, 8.0, 16.0]);

    Ok(())
}

#[tokio::test]
async fn delete_with_float16_predicate() -> DeltaResult<()> {
    let (table, _) = setup_table().await?;

    let (table, metrics) = table.delete().with_predicate("x >= 2.5").await?;
    assert_eq!(table.version(), Some(1));
    assert!(metrics.num_deleted_rows.is_some_and(|r| r == 2));

    let batches = get_data(table).await;
    assert_eq!(sorted_values(batches), vec![1.0]);

    Ok(())
}

#[tokio::test]
async fn update_with_float16() -> DeltaResult<()> {
    let (table, _) = setup_table().await?;

    let (table, metrics) = table
        .update()
        .with_predicate("x >= 2.5")
        .with_update("x", "8.0")
        .await?;
    assert_eq!(table.version(), Some(1));
    assert_eq!(metrics.num_updated_rows, 2);

    let batches = get_data(table).await;
    assert_eq!(sorted_values(batches), vec![1.0, 8.0, 8.0]);

    Ok(())
}

#[tokio::test]
async fn merge_with_float16() -> DeltaResult<()> {
    use datafusion::common::ScalarValue;
    use datafusion::logical_expr::{col, lit};

    let (table, arrow_schema) = setup_table().await?;

    let matched_update: f32 = 16.0;
    let inserted: f32 = 8.0;

    // Source row 1 matches a target row (2.5), row 2 does not (8.0).
    let source_batch = RecordBatch::try_new(
        arrow_schema.clone(),
        vec![float16_array(vec![2.5, inserted])],
    )?;

    let ctx: SessionContext = create_session().into();
    let source = ctx.read_batch(source_batch)?;

    let (table, metrics) = table
        .merge(source, col("target.x").eq(col("source.x")))
        .with_source_alias("source")
        .with_target_alias("target")
        .when_matched_update(|update| {
            update.update(
                "x",
                lit(ScalarValue::Float16(Some(f16::from_f32(matched_update)))),
            )
        })?
        .when_not_matched_insert(|insert| insert.set("x", col("source.x")))?
        .await?;

    assert_eq!(table.version(), Some(1));
    assert_eq!(metrics.num_target_rows_updated, 1);
    assert_eq!(metrics.num_target_rows_inserted, 1);

    let batches = get_data(table).await;
    assert_eq!(
        sorted_values(batches),
        vec![1.0, 4.0, inserted, matched_update]
    );

    Ok(())
}
