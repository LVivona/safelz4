use super::error::LZ4Exception;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use pyo3::Bound as PyBound;

/// Compress all bytes of input into output. The method chooses an appropriate hashtable to lookup duplicates. output should be preallocated with a size of get_maximum_output_size.
///
/// Args:
///     input (`bytes`):
///         decompressed planetext buffer converted.
///     output (`bytesarray`):
///          output buffer to write compressed data into
/// Returns:
///     (`bytes`):
///         The compressed bytes of the buffer.
#[pyfunction]
#[pyo3(signature = (input, output))]
fn compress_into(input: &[u8], output: PyBound<'_, PyByteArray>) -> PyResult<usize> {
    let out = unsafe { output.as_bytes_mut() };
    let size =
        lz4_flex::compress_into(input, out).map_err(|e| LZ4Exception::new_err(format!("{e}")))?;

    Ok(size)
}

/// Compress all bytes of input into output. The uncompressed size will be prepended as a little endian u32. Can be used in conjunction with decompress_size_prepended
///
/// Args:
///     input (`bytes`):
///         decompressed planetext buffer converted.
///
/// Returns:
///     (`bytes`):
///         The compressed bytes of the buffer.
#[pyfunction]
#[pyo3(signature = (input))]
fn compress_prepend_size<'py>(py: Python<'py>, input: &[u8]) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::compress_prepend_size(input);
    let pybytes = PyBytes::new(py, &output);
    Ok(pybytes)
}

/// Compress all bytes of input.
///
/// Args:
///     input (`bytes`):
///         abirtary set of bytes.
/// Returns:
///     `bytes`: lz4 compressed block.
#[pyfunction]
#[pyo3(signature = (input))]
fn compress<'py>(py: Python<'py>, input: &[u8]) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::compress(input);
    Ok(PyBytes::new(py, &output))
}

#[pyfunction]
#[pyo3(signature = (input, ext_dict))]
fn compress_with_dict<'py>(
    py: Python<'py>,
    input: &[u8],
    ext_dict: &[u8],
) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::block::compress_with_dict(input, ext_dict);
    Ok(PyBytes::new(py, &output))
}

/// Decompress all bytes of input into output. output should be preallocated with a size of of the uncompressed data.
///
/// Args:
///     buffer (`bytes`):
///         compressed bytes format, of an abritrary size
///     output (`bytearray`):
///         mutable buffer that allows to write out the bytes
/// Returns:
///     `int`: size of the bytes compressed
#[pyfunction]
#[pyo3(signature = (input, output))]
fn decompress_into(input: &[u8], output: PyBound<'_, PyByteArray>) -> PyResult<usize> {
    let length = input.len();
    let max_length = lz4_flex::block::get_maximum_output_size(length);
    let output_ref = unsafe { output.as_bytes_mut() };

    if output_ref.len() > max_length {
        return Err(LZ4Exception::new_err(
            "bytearray exceeds the max output size of the data.",
        ));
    }

    let size = lz4_flex::decompress_into(input, output_ref)
        .map_err(|e| LZ4Exception::new_err(format!("decompression error {e:?}")))?;
    Ok(size)
}

///

#[pyfunction]
#[pyo3(signature = (input, min_size))]
fn decompress<'py>(
    py: Python<'py>,
    input: &[u8],
    min_size: usize,
) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::decompress(input, min_size)
        .map_err(|e| LZ4Exception::new_err(format!("{e:?} has occued")))?;
    Ok(PyBytes::new(py, &output))
}

/// Decompress input bytes that were compressed with the original size prepended.
/// Compatible with `compress_prepend_size`.
///
/// Args:
///     input (`bytes`):
///         fixed set of bytes to be decompressed
///
// Returns:
///     `bytes`: Decompressed data.
#[pyfunction]
#[pyo3(signature = (input))]
fn decompress_size_prepended<'py>(
    py: Python<'py>,
    input: &[u8],
) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::decompress_size_prepended(input)
        .map_err(|e| LZ4Exception::new_err(format!("decompression error {e:?}")))?;
    let pybytes = PyBytes::new(py, &output);
    Ok(pybytes)
}

/// Decompress input bytes using a user-provided dictionary of bytes.
/// Args:
///     input (`bytes`):
///         fixed set of bytes to be decompressed.
///     ext_dict (`bytes`):
///         Dictionary used for decompression.
///
/// Returns:
///     `bytes`: Decompressed data.
#[pyfunction]
#[pyo3(signature = (input, ext_dict))]
fn decompress_with_dict<'py>(
    py: Python<'py>,
    input: &[u8],
    ext_dict: &[u8],
) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::block::compress_prepend_size_with_dict(input, ext_dict);
    Ok(PyBytes::new(py, &output))
}

/// pyo3 register _block module
///
/// ```ignore
/// from .safelz4_rs import _block
///
/// plaintext = b"eeeeeeee Hello world this is an example of plaintext being compressed eeeeeeeeeeeeeee"
/// output = _block.compresss(plaintext)
/// output = _block.decompress(output)
/// ```
pub(crate) fn register_block_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let block_m = PyModule::new(m.py(), "_block")?;
    block_m.add_function(wrap_pyfunction!(compress, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(compress_into, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(compress_prepend_size, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(compress_with_dict, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(decompress, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(decompress_into, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(decompress_size_prepended, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(decompress_with_dict, &block_m)?)?;

    m.add_submodule(&block_m)?;
    Ok(())
}
