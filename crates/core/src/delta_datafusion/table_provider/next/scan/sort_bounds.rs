//! Per-file sort boundary metadata carried in Add action tags.
//!
//! Column-wise min/max statistics cannot describe the *first* and *last* row
//! of a file sorted on multiple columns: for a file sorted on `(day, hour)`
//! holding rows `[(1, 2), (2, 0)]`, the composed min row `(1, 0)` and max row
//! `(2, 2)` bound the real boundary rows `(1, 2)` and `(2, 0)` only loosely.
//! Overlap checks between files built on composed min/max therefore reject
//! boundary-touching files that do not actually overlap.
//!
//! Writers that produce files sorted on a declared order can record the exact
//! sort-key values of each file's first and last row in the file's Add action
//! `tags`, under [`FILE_SORT_BOUNDS_TAG`]. The tag value is a JSON document:
//!
//! ```json
//! {
//!   "columns": [
//!     {"name": "day", "descending": false, "nullsFirst": false},
//!     {"name": "hour", "descending": false, "nullsFirst": false}
//!   ],
//!   "first": ["1", "2"],
//!   "last": ["2", "0"]
//! }
//! ```
//!
//! `columns` is the sort order the file is sorted by (logical column names);
//! `first` and `last` hold the sort-key values of the file's first and last
//! row, aligned with `columns`. Values use the Delta partition-value string
//! serialization ([`ScalarExt::serialize`] / [`PrimitiveType::parse_scalar`]),
//! with JSON `null` for null values. Recording the sort order in the tag makes
//! each file self-describing: readers only use the bounds when the declared
//! scan sort order is a per-column prefix match of the file's recorded order.
//!
//! The tag is advisory metadata with the same trust model as
//! [`with_file_sort_order`](crate::delta_datafusion::TableProviderBuilder::with_file_sort_order):
//! it asserts that the file is internally sorted as recorded. Files without
//! the tag (or with an incompatible recorded order) simply fall back to
//! composed min/max statistics.

use std::cmp::Ordering;
use std::collections::HashMap;

use arrow_schema::{DataType as ArrowDataType, TimeUnit};
use datafusion::common::{ScalarValue, Statistics};
use datafusion::physical_expr::LexOrdering;
use datafusion::physical_expr::expressions::Column;
use delta_kernel::expressions::Scalar;
use delta_kernel::schema::PrimitiveType;
use serde::{Deserialize, Serialize};

use crate::delta_datafusion::engine::to_datafusion_scalar;
use crate::delta_datafusion::table_provider::FileSortColumn;
use crate::kernel::scalars::ScalarExt;

/// Add action tag key holding a file's sort order and boundary-row values.
pub const FILE_SORT_BOUNDS_TAG: &str = "delta-rs.fileSortBounds";

/// One sort column entry in the tag document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TagSortColumn {
    name: String,
    descending: bool,
    #[serde(rename = "nullsFirst")]
    nulls_first: bool,
}

impl TagSortColumn {
    fn matches(&self, declared: &FileSortColumn) -> bool {
        self.name == declared.column
            && self.descending == declared.descending
            && self.nulls_first == declared.nulls_first
    }
}

/// The JSON document stored under [`FILE_SORT_BOUNDS_TAG`].
#[derive(Debug, Serialize, Deserialize)]
struct SortBoundsTag {
    columns: Vec<TagSortColumn>,
    first: Vec<Option<String>>,
    last: Vec<Option<String>>,
}

/// Sort-key boundary rows of a file (or group of files), aligned with a
/// prefix of the declared file sort order.
///
/// Contract: every row lies between `first` and `last` under the declared
/// order's lexicographic total order, and `first` precedes (or equals) `last`.
/// Tag-derived bounds ([`parse_file_sort_bounds`]) are the *exact* boundary
/// rows; statistics-derived bounds ([`bounds_from_statistics`]) are the
/// conservative composed min/max rows, which bound the same interval loosely.
/// Both are valid inputs to [`compare_bound_rows`]-based overlap checks — a
/// loose bound can only make the check reject more, never accept wrongly.
/// Values are non-null by construction (both constructors reject nulls).
///
/// Caveat on the containment contract: min/max statistics exclude nulls, so
/// statistics-derived bounds only contain *all* rows when the sort columns
/// are provably null-free for the file — null rows sort outside the composed
/// interval. Tag-derived bounds are real rows of a file sorted with its
/// declared null placement, so they contain null rows too. Consumers that
/// rely on full containment must gate statistics-derived bounds accordingly
/// (see the scan grouping's `order_files_by_bounds`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FileSortBounds {
    /// Sort-key values of the first row (directional: for a descending
    /// column this is the largest value).
    pub first: Vec<ScalarValue>,
    /// Sort-key values of the last row.
    pub last: Vec<ScalarValue>,
}

impl FileSortBounds {
    /// Truncate the boundary rows to the first `len` sort columns. A prefix
    /// of a valid bound is a valid bound for the prefix ordering.
    pub(crate) fn truncated(mut self, len: usize) -> Self {
        self.first.truncate(len);
        self.last.truncate(len);
        self
    }
}

/// Per-partition sort boundary rows for a scan whose partitions are
/// contiguous, range-ordered, mutually non-overlapping (allowing touching
/// boundaries) chunks of a file list sorted on `ordering`.
///
/// Concatenating the partitions in order therefore yields a stream sorted on
/// `ordering` (non-strictly). Entry `i` bounds all rows of scan partition `i`.
#[derive(Debug, Clone)]
pub(crate) struct ScanSortBounds {
    /// The ordering the bounds are expressed in, over the schema of the plan
    /// node that carries them.
    pub ordering: LexOrdering,
    /// Boundary rows per scan partition, aligned with partition indexes.
    pub partitions: Vec<FileSortBounds>,
}

/// Compare two boundary rows under `ordering`'s per-column directions.
///
/// Standard lexicographic walk: the first strictly ordered column decides,
/// equal columns defer to the next. Returns `None` when any column pair is
/// incomparable (mixed types); values are expected non-null (null boundary
/// rows are rejected at construction).
pub(crate) fn compare_bound_rows(
    a: &[ScalarValue],
    b: &[ScalarValue],
    ordering: &LexOrdering,
) -> Option<Ordering> {
    for (idx, sort_expr) in ordering.iter().enumerate() {
        let cmp = a.get(idx)?.partial_cmp(b.get(idx)?)?;
        let cmp = if sort_expr.options.descending {
            cmp.reverse()
        } else {
            cmp
        };
        if cmp != Ordering::Equal {
            return Some(cmp);
        }
    }
    Some(Ordering::Equal)
}

/// Conservative boundary rows composed from per-column min/max statistics.
///
/// The composed first row (per-column min, or max for descending columns)
/// lexicographically precedes the file's real first row, and the composed
/// last row follows the real last row, so the returned interval is a superset
/// of the file's true row range. Requires exact, non-null min/max for every
/// sort column; returns `None` otherwise.
pub(crate) fn bounds_from_statistics(
    stats: &Statistics,
    ordering: &LexOrdering,
) -> Option<FileSortBounds> {
    let mut first = Vec::with_capacity(ordering.len());
    let mut last = Vec::with_capacity(ordering.len());
    for sort_expr in ordering.iter() {
        let column = sort_expr.expr.downcast_ref::<Column>()?;
        let col_stats = stats.column_statistics.get(column.index())?;
        if !(col_stats.min_value.is_exact()? && col_stats.max_value.is_exact()?) {
            return None;
        }
        let min = col_stats.min_value.get_value()?.clone();
        let max = col_stats.max_value.get_value()?.clone();
        // All-null or empty files report null min/max; they prove nothing.
        if min.is_null() || max.is_null() {
            return None;
        }
        let (start, end) = if sort_expr.options.descending {
            (max, min)
        } else {
            (min, max)
        };
        first.push(start);
        last.push(end);
    }
    Some(FileSortBounds { first, last })
}

/// Parse a file's [`FILE_SORT_BOUNDS_TAG`] tag into boundary values for the
/// declared sort order.
///
/// `declared` is the scan's sort order (possibly already truncated to the
/// columns present in the read schema) and `column_types` the corresponding
/// arrow types, in the same order. Returns `None` — falling back to min/max
/// statistics — when the tag is absent or malformed, when the declared order
/// is not a per-column prefix match (name, direction, null placement) of the
/// file's recorded order, or when any boundary value within the declared
/// prefix is null.
pub(crate) fn parse_file_sort_bounds(
    tags: &HashMap<String, Option<String>>,
    declared: &[FileSortColumn],
    column_types: &[ArrowDataType],
) -> Option<FileSortBounds> {
    debug_assert_eq!(declared.len(), column_types.len());
    if declared.is_empty() || declared.len() != column_types.len() {
        return None;
    }
    let raw = tags.get(FILE_SORT_BOUNDS_TAG)?.as_ref()?;
    let tag: SortBoundsTag = serde_json::from_str(raw).ok()?;
    if tag.first.len() != tag.columns.len()
        || tag.last.len() != tag.columns.len()
        || tag.columns.len() < declared.len()
    {
        return None;
    }
    if !declared
        .iter()
        .zip(&tag.columns)
        .all(|(declared, recorded)| recorded.matches(declared))
    {
        return None;
    }

    let mut first = Vec::with_capacity(declared.len());
    let mut last = Vec::with_capacity(declared.len());
    for (idx, data_type) in column_types.iter().enumerate() {
        first.push(parse_boundary_value(tag.first[idx].as_deref()?, data_type)?);
        last.push(parse_boundary_value(tag.last[idx].as_deref()?, data_type)?);
    }
    Some(FileSortBounds { first, last })
}

/// Parse one serialized boundary value into the [`ScalarValue`] representation
/// used by file statistics, so tag-derived and statistics-derived values stay
/// mutually comparable.
fn parse_boundary_value(raw: &str, data_type: &ArrowDataType) -> Option<ScalarValue> {
    let primitive = primitive_type_for_arrow(data_type)?;
    // `parse_scalar` maps the empty string to null (a partition-value
    // convention); an empty string is a legitimate boundary value.
    let scalar = if matches!(primitive, PrimitiveType::String) {
        Scalar::String(raw.to_string())
    } else {
        primitive.parse_scalar(raw).ok()?
    };
    if scalar.is_null() {
        return None;
    }
    to_datafusion_scalar(&scalar).ok()
}

/// The Delta primitive type whose partition-value string serialization to use
/// for a sort column with the given arrow type in the parquet read schema.
fn primitive_type_for_arrow(data_type: &ArrowDataType) -> Option<PrimitiveType> {
    use ArrowDataType as A;
    Some(match data_type {
        A::Utf8 | A::LargeUtf8 | A::Utf8View => PrimitiveType::String,
        A::Binary | A::LargeBinary | A::BinaryView => PrimitiveType::Binary,
        A::Boolean => PrimitiveType::Boolean,
        A::Int8 => PrimitiveType::Byte,
        A::Int16 => PrimitiveType::Short,
        A::Int32 => PrimitiveType::Integer,
        A::Int64 => PrimitiveType::Long,
        A::Float32 => PrimitiveType::Float,
        A::Float64 => PrimitiveType::Double,
        A::Date32 => PrimitiveType::Date,
        A::Timestamp(TimeUnit::Microsecond, Some(_)) => PrimitiveType::Timestamp,
        A::Timestamp(TimeUnit::Microsecond, None) => PrimitiveType::TimestampNtz,
        A::Decimal128(precision, scale) if *scale >= 0 => {
            PrimitiveType::decimal(*precision, u8::try_from(*scale).ok()?).ok()?
        }
        _ => return None,
    })
}

/// Encode a file's sort order and boundary rows as the value for the
/// [`FILE_SORT_BOUNDS_TAG`] tag.
///
/// `first` and `last` are the sort-key values of the file's first and last
/// row, aligned with `columns`. Null scalars are encoded as JSON `null`.
/// Intended for writers producing sorted files (and for tests); the inverse of
/// [`parse_file_sort_bounds`].
// The write side (populating tags at file-creation time) is a follow-up;
// until then this is exercised by the round-trip tests only.
#[allow(dead_code)]
pub(crate) fn encode_file_sort_bounds(
    columns: &[FileSortColumn],
    first: &[Scalar],
    last: &[Scalar],
) -> String {
    let encode_row = |values: &[Scalar]| {
        values
            .iter()
            // Disambiguated call: kernel scalars also implement serde's
            // `Serialize`, which shares the method name.
            .map(|value| (!value.is_null()).then(|| ScalarExt::serialize(value)))
            .collect::<Vec<_>>()
    };
    let tag = SortBoundsTag {
        columns: columns
            .iter()
            .map(|column| TagSortColumn {
                name: column.column.clone(),
                descending: column.descending,
                nulls_first: column.nulls_first,
            })
            .collect(),
        first: encode_row(first),
        last: encode_row(last),
    };
    serde_json::to_string(&tag).expect("sort bounds tag serializes to JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags_with(value: &str) -> HashMap<String, Option<String>> {
        HashMap::from([(FILE_SORT_BOUNDS_TAG.to_string(), Some(value.to_string()))])
    }

    fn day_hour_columns() -> Vec<FileSortColumn> {
        vec![FileSortColumn::asc("day"), FileSortColumn::asc("hour")]
    }

    #[test]
    fn round_trips_integer_bounds() {
        let columns = day_hour_columns();
        let encoded = encode_file_sort_bounds(
            &columns,
            &[Scalar::Long(1), Scalar::Long(2)],
            &[Scalar::Long(2), Scalar::Long(0)],
        );
        let bounds = parse_file_sort_bounds(
            &tags_with(&encoded),
            &columns,
            &[ArrowDataType::Int64, ArrowDataType::Int64],
        )
        .expect("bounds should parse");
        assert_eq!(
            bounds.first,
            vec![ScalarValue::Int64(Some(1)), ScalarValue::Int64(Some(2))]
        );
        assert_eq!(
            bounds.last,
            vec![ScalarValue::Int64(Some(2)), ScalarValue::Int64(Some(0))]
        );
    }

    #[test]
    fn round_trips_timestamp_and_string_bounds() {
        let columns = vec![FileSortColumn::asc("ts"), FileSortColumn::asc("name")];
        // 2021-01-01 00:00:00.123456 UTC in microseconds.
        let ts = 1_609_459_200_123_456_i64;
        let encoded = encode_file_sort_bounds(
            &columns,
            &[Scalar::Timestamp(ts), Scalar::String("".to_string())],
            &[Scalar::Timestamp(ts + 1), Scalar::String("zzz".to_string())],
        );
        let types = [
            ArrowDataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            ArrowDataType::Utf8,
        ];
        let bounds = parse_file_sort_bounds(&tags_with(&encoded), &columns, &types)
            .expect("bounds should parse");
        assert_eq!(
            bounds.first[0],
            ScalarValue::TimestampMicrosecond(Some(ts), Some("UTC".into()))
        );
        // The empty string must survive as a value, not collapse to null.
        assert_eq!(bounds.first[1], ScalarValue::Utf8(Some(String::new())));
        assert_eq!(
            bounds.last[0],
            ScalarValue::TimestampMicrosecond(Some(ts + 1), Some("UTC".into()))
        );
        assert_eq!(bounds.last[1], ScalarValue::Utf8(Some("zzz".to_string())));
    }

    #[test]
    fn declared_prefix_of_recorded_order_is_accepted() {
        let recorded = vec![
            FileSortColumn::asc("day"),
            FileSortColumn::asc("hour"),
            FileSortColumn::asc("minute"),
        ];
        let encoded = encode_file_sort_bounds(
            &recorded,
            &[Scalar::Long(1), Scalar::Long(2), Scalar::Long(3)],
            &[Scalar::Long(2), Scalar::Long(0), Scalar::Long(4)],
        );
        // Declared order is a two-column prefix: bounds truncate to it.
        let bounds = parse_file_sort_bounds(
            &tags_with(&encoded),
            &day_hour_columns(),
            &[ArrowDataType::Int64, ArrowDataType::Int64],
        )
        .expect("prefix of the recorded order should be usable");
        assert_eq!(bounds.first.len(), 2);
        assert_eq!(bounds.last[1], ScalarValue::Int64(Some(0)));
    }

    #[test]
    fn declared_order_longer_than_recorded_is_rejected() {
        let recorded = vec![FileSortColumn::asc("day")];
        let encoded = encode_file_sort_bounds(&recorded, &[Scalar::Long(1)], &[Scalar::Long(2)]);
        assert!(
            parse_file_sort_bounds(
                &tags_with(&encoded),
                &day_hour_columns(),
                &[ArrowDataType::Int64, ArrowDataType::Int64],
            )
            .is_none()
        );
    }

    #[test]
    fn mismatched_direction_or_nulls_or_name_is_rejected() {
        let declared = day_hour_columns();
        let types = [ArrowDataType::Int64, ArrowDataType::Int64];
        for recorded in [
            vec![FileSortColumn::desc("day"), FileSortColumn::asc("hour")],
            vec![
                FileSortColumn::asc("day").with_nulls_first(true),
                FileSortColumn::asc("hour"),
            ],
            vec![FileSortColumn::asc("day"), FileSortColumn::asc("minute")],
        ] {
            let encoded = encode_file_sort_bounds(
                &recorded,
                &[Scalar::Long(1), Scalar::Long(2)],
                &[Scalar::Long(2), Scalar::Long(0)],
            );
            assert!(
                parse_file_sort_bounds(&tags_with(&encoded), &declared, &types).is_none(),
                "recorded order {recorded:?} must not satisfy the declared order"
            );
        }
    }

    #[test]
    fn null_boundary_value_is_rejected() {
        let columns = day_hour_columns();
        let encoded = encode_file_sort_bounds(
            &columns,
            &[
                Scalar::Long(1),
                Scalar::Null(delta_kernel::schema::DataType::LONG),
            ],
            &[Scalar::Long(2), Scalar::Long(0)],
        );
        assert!(
            parse_file_sort_bounds(
                &tags_with(&encoded),
                &columns,
                &[ArrowDataType::Int64, ArrowDataType::Int64],
            )
            .is_none()
        );
    }

    #[test]
    fn missing_or_malformed_tag_is_rejected() {
        let declared = day_hour_columns();
        let types = [ArrowDataType::Int64, ArrowDataType::Int64];
        assert!(parse_file_sort_bounds(&HashMap::new(), &declared, &types).is_none());
        assert!(
            parse_file_sort_bounds(
                &HashMap::from([(FILE_SORT_BOUNDS_TAG.to_string(), None)]),
                &declared,
                &types,
            )
            .is_none()
        );
        assert!(parse_file_sort_bounds(&tags_with("not json"), &declared, &types).is_none());
        // Value arrays shorter than the recorded column list.
        assert!(
            parse_file_sort_bounds(
                &tags_with(r#"{"columns":[{"name":"day","descending":false,"nullsFirst":false},{"name":"hour","descending":false,"nullsFirst":false}],"first":["1"],"last":["2","0"]}"#),
                &declared,
                &types,
            )
            .is_none()
        );
    }
}
