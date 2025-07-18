//! Fallback implementation of encryption options for when DataFusion is disabled

use crate::DeltaResult;
use arrow_schema::Schema;
use parquet::file::properties::WriterPropertiesBuilder;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct TableEncryption {
    _empty: (),
}

impl TableEncryption {
    pub fn update_writer_properties(
        &self,
        builder: WriterPropertiesBuilder,
        _file_path: &str,
        _file_schema: &Arc<Schema>,
    ) -> DeltaResult<WriterPropertiesBuilder> {
        Ok(builder)
    }
}
