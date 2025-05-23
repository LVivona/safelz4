use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use pyo3::PyResult;

// Python binded exception for LZ4 file format.
pyo3::create_exception!(
    safelz4,
    LZ4Exception,
    PyException,
    "Custom Base exception for LZ4 frame/block compression"
);

// Python bindined to base exception
pyo3::create_exception!(
    safelz4,
    ReadError,
    LZ4Exception,
    "Custom error is raised when a lz4 is opened, that either cannot be handled by the safelz4 module or is somehow invalid."
);

pyo3::create_exception!(
    safelz4,
    HeaderError,
    LZ4Exception,
    "Custom error is raised when frame header is invalid or unreadable."
);

pyo3::create_exception!(
    safelz4,
    CompressionError,
    LZ4Exception,
    "Custom error is raised when a compression method is not supported or when the data cannot be encoded properly."
);

pyo3::create_exception!(
    safelz4,
    DecompressionError,
    LZ4Exception,
    "Custom error is raised when a decompression method is not supported or when the data cannot be decoded properly."
);

pyo3::create_exception!(
    safelz4,
    LZ4BlockError,
    LZ4Exception,
    "Custom error raised when block compression is invalid"
);

/// register error module for LZ4 pyo3 exception recived within the rust code.
/// ```ignore
/// from ._safelz4_rs import error, _block
/// try:
///     _ = _block.compress(b"")
/// except error.LZ4Exception as e
///     raise e
/// ```
pub(crate) fn register_error_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let error_m = PyModule::new(m.py(), "_error")?;
    error_m.add("LZ4Exception", error_m.py().get_type::<LZ4Exception>())?;

    // frame exception
    error_m.add("ReadError", error_m.py().get_type::<ReadError>())?;
    error_m.add("HeaderError", error_m.py().get_type::<HeaderError>())?;
    error_m.add(
        "CompressionError",
        error_m.py().get_type::<CompressionError>(),
    )?;
    error_m.add(
        "DecompressionError",
        error_m.py().get_type::<DecompressionError>(),
    )?;

    // block exception
    error_m.add("LZ4BlockError", error_m.py().get_type::<LZ4BlockError>())?;

    m.add_submodule(&error_m)?;
    Ok(())
}
