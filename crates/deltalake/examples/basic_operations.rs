use deltalake::arrow::{
    array::{Int32Array, StringArray, TimestampMicrosecondArray},
    datatypes::{DataType as ArrowDataType, Field, Schema as ArrowSchema, TimeUnit},
    record_batch::RecordBatch,
};
use deltalake::kernel::{DataType, PrimitiveType, StructField};
use deltalake::operations::collect_sendable_stream;
use deltalake::parquet::file::properties::WriterProperties;
use deltalake::{parquet, DeltaOps};
use std::fs;

use deltalake::datafusion::config::TableParquetOptions;
use deltalake::parquet::encryption::decrypt::FileDecryptionProperties;
use deltalake::parquet::encryption::encrypt::FileEncryptionProperties;
use deltalake_core::{DeltaTable, DeltaTableError};
use std::sync::Arc;

fn get_table_columns() -> Vec<StructField> {
    vec![
        StructField::new(
            String::from("int"),
            DataType::Primitive(PrimitiveType::Integer),
            false,
        ),
        StructField::new(
            String::from("string"),
            DataType::Primitive(PrimitiveType::String),
            true,
        ),
        StructField::new(
            String::from("timestamp"),
            DataType::Primitive(PrimitiveType::TimestampNtz),
            true,
        ),
    ]
}

fn get_table_batches() -> RecordBatch {
    let schema = Arc::new(ArrowSchema::new(vec![
        Field::new("int", ArrowDataType::Int32, false),
        Field::new("string", ArrowDataType::Utf8, true),
        Field::new(
            "timestamp",
            ArrowDataType::Timestamp(TimeUnit::Microsecond, None),
            true,
        ),
    ]));

    let int_values = Int32Array::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    let str_values = StringArray::from(vec!["A", "B", "A", "B", "A", "A", "A", "B", "B", "A", "A"]);
    let ts_values = TimestampMicrosecondArray::from(vec![
        1000000012, 1000000012, 1000000012, 1000000012, 500012305, 500012305, 500012305, 500012305,
        500012305, 500012305, 500012305,
    ]);
    RecordBatch::try_new(
        schema,
        vec![
            Arc::new(int_values),
            Arc::new(str_values),
            Arc::new(ts_values),
        ],
    )
    .unwrap()
}

async fn create_table(
    uri: &str,
    table_name: &str,
    crypt: &FileEncryptionProperties,
) -> Result<DeltaTable, DeltaTableError> {
    fs::remove_dir_all(uri)?;
    let ops = DeltaOps::try_from_uri(uri).await?;

    // The operations module uses a builder pattern that allows specifying several options
    // on how the command behaves. The builders implement `Into<Future>`, so once
    // options are set you can run the command using `.await`.
    let table = ops
        .create()
        .with_columns(get_table_columns())
        // .with_partition_columns(["timestamp"])
        .with_table_name(table_name)
        .with_comment("A table to show how delta-rs works")
        .await?;

    assert_eq!(table.version(), Some(0));

    let writer_properties = WriterProperties::builder()
        // .set_compression(Compression::ZSTD(ZstdLevel::try_new(3).unwrap()))
        .with_file_encryption_properties(crypt.clone())
        .build();

    let batch = get_table_batches();
    let table = DeltaOps(table)
        .write(vec![batch.clone()])
        .with_writer_properties(writer_properties.clone())
        .await?;

    assert_eq!(table.version(), Some(1));

    // To overwrite instead of append (which is the default), use `.with_save_mode`:
    let table = DeltaOps(table)
        .write(vec![batch.clone()])
        // .with_save_mode(SaveMode::Overwrite)
        .with_writer_properties(writer_properties.clone())
        .await?;

    assert_eq!(table.version(), Some(2));

    Ok(table)
}

async fn read_table(
    uri: &str,
    decryption_properties: &FileDecryptionProperties,
) -> Result<(), deltalake::errors::DeltaTableError> {
    let table = deltalake::open_table(String::from(uri)).await?;
    let mut parquet_options = TableParquetOptions::default();
    parquet_options.crypto.file_decryption = Some(decryption_properties.into());
    let (_table, stream) = DeltaOps(table)
        .load()
        .with_parquet_options(parquet_options)
        .await?;
    let data: Vec<RecordBatch> = collect_sendable_stream(stream).await?;

    println!("{data:?}");

    Ok(())
}

async fn round_trip_test() -> Result<(), deltalake::errors::DeltaTableError> {
    let mut uri = std::env::current_dir().unwrap();
    uri.push("encrypted_roundtrip");
    let uri = uri.to_str().unwrap();

    println!("Using table URI {uri}");

    let table_name = "roundtrip";
    let key: Vec<_> = b"1234567890123450".to_vec();
    let wrong_key: Vec<_> = b"9234567890123450".to_vec();

    let crypt = parquet::encryption::encrypt::FileEncryptionProperties::builder(key.clone())
        .with_column_key("int", key.clone())
        .with_column_key("string", key.clone())
        .build()?;

    let decrypt = FileDecryptionProperties::builder(key.clone())
        .with_column_key("int", key.clone())
        .with_column_key("string", key.clone())
        .build()?;

    create_table(uri, table_name, &crypt).await?;
    read_table(uri, &decrypt).await?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), deltalake::errors::DeltaTableError> {
    round_trip_test().await?;
    Ok(())
}
