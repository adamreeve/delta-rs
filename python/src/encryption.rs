use pyo3::{prelude::*, IntoPyObjectExt};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::types::{PyBytes, PyString};
use deltalake::parquet::errors::ParquetError;

// KMS client trait that would live in arrow-rs.
pub trait KmsClient: Send + Sync {
    fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String, ParquetError>;

    fn unwrap_key(&self, wrapped_key: &str, master_key_identifier: &str) -> Result<Vec<u8>, ParquetError>;
}

pub struct PyKmsClient {
    py_client: Py<PyAny>,
}

impl PyKmsClient {
    pub fn new<'py>(py_client: Bound<'py, PyAny>) -> PyResult<Self> {
        let py = py_client.py();
        let kms_base = PyModule::import(py, "deltalake.encryption")?.getattr("KmsClient")?;
        if !py_client.is_instance(&kms_base)? {
            return Err(PyErr::new::<PyTypeError, _>("Expected an instance of KmsClient"));
        }

        Ok(Self {
            py_client: py_client.unbind(),
        })
    }
}

impl KmsClient for PyKmsClient {
    fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String, ParquetError> {
        Python::with_gil(|py| {
            let py_client = self.py_client.bind(py);
            let py_key = PyBytes::new(py, key_bytes);
            let py_identifier = PyString::new(py, master_key_identifier);
            let args = (py_key, py_identifier);
            let wrap_method = py_client.getattr("wrap_key").map_err(|e| ParquetError::General(e.to_string()))?;
            let wrapped = wrap_method.call1(args).map_err(|e| ParquetError::General(e.to_string()))?;
            let wrapped: String = wrapped.extract().map_err(|e| ParquetError::General(e.to_string()))?;
            Ok(wrapped)
        })
    }

    fn unwrap_key(&self, wrapped_key: &str, master_key_identifier: &str) -> Result<Vec<u8>, ParquetError> {
        Python::with_gil(|py| {
            let py_client = self.py_client.bind(py);
            let py_wrapped = PyString::new(py, wrapped_key);
            let py_identifier = PyString::new(py, master_key_identifier);
            let args = (py_wrapped, py_identifier);
            let unwrap_method = py_client.getattr("unwrap_key").map_err(|e| ParquetError::General(e.to_string()))?;
            let unwrapped = unwrap_method.call1(args).map_err(|e| ParquetError::General(e.to_string()))?;
            let unwrapped: Vec<u8> = unwrapped.extract().map_err(|e| ParquetError::General(e.to_string()))?;
            Ok(unwrapped)
        })
    }
}