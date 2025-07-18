use crate::operations::encryption::TableEncryption;
use crate::{crate_version, DeltaResult, DeltaTable, DeltaTableError};
use arrow_schema::Schema;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use parquet::schema::types::ColumnPath;
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct WriterPropertiesFactory {
    overridden_properties: Option<WriterProperties>,
    encryption: Option<TableEncryption>,
    compression: Option<Compression>,
}

impl WriterPropertiesFactory {
    const DEFAULT_COMPRESSION: Compression = Compression::SNAPPY;

    pub fn for_table(table: &DeltaTable) -> WriterPropertiesFactory {
        let mut writer_properties_factory = WriterPropertiesFactory::default();
        if let Some(encryption) = &table.encryption_config {
            writer_properties_factory.set_encryption(encryption.clone());
        }
        writer_properties_factory
    }

    pub fn set_properties(&mut self, properties: WriterProperties) {
        self.overridden_properties = Some(properties);
    }

    pub fn set_encryption(&mut self, encryption: TableEncryption) {
        self.encryption = Some(encryption);
    }

    pub fn set_compression(&mut self, compression: Compression) {
        self.compression = Some(compression);
    }

    pub(crate) fn compression(&self, column_path: &ColumnPath) -> Compression {
        if let Some(properties) = self.overridden_properties.as_ref() {
            properties.compression(column_path)
        } else if let Some(compression) = self.compression {
            compression
        } else {
            Self::DEFAULT_COMPRESSION
        }
    }

    pub(crate) fn create_writer_properties(
        &self,
        file_path: &str,
        file_schema: &Arc<Schema>,
    ) -> DeltaResult<WriterProperties> {
        if let Some(properties) = self.overridden_properties.as_ref() {
            if self.encryption.is_some() {
                return Err(DeltaTableError::Generic(
                    "Cannot specify both Parquet WriterProperties and table encryption".to_owned(),
                ));
            }
            Ok(properties.clone())
        } else {
            let compression = self.compression.unwrap_or(Self::DEFAULT_COMPRESSION);
            let mut builder = WriterProperties::builder()
                .set_compression(compression)
                .set_created_by(format!("delta-rs version {}", crate_version()));
            if let Some(encryption) = self.encryption.as_ref() {
                builder = encryption.update_writer_properties(builder, file_path, file_schema)?;
            }
            Ok(builder.build())
        }
    }
}
