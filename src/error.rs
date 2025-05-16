use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use pyo3::PyResult;

// Python binded exception for LZ4 file format.
pyo3::create_exception!(
    safelz4,
    LZ4Exception,
    PyException,
    "Custom Python Exception for LZ4 errors."
);

/// register error module for LZ4 pyo3 exception recived within the rust code.
/// ```ignore
/// from .safelz4_rs import error, _block
/// try:
///     _ = _block.compress(b"")
/// except error.LZ4Exception as e
///     raise e
/// ```
pub(crate) fn register_error_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let error_m = PyModule::new(m.py(), "error")?;
    error_m.add("LZ4Exception", error_m.py().get_type::<LZ4Exception>())?;

    m.add_submodule(&error_m)?;
    Ok(())
}
