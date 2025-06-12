use super::error::LZ4BlockError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use pyo3::Bound as PyBound;

/// Obtain the maximum output size of the block
///
/// Args:
///     input_len (`int`):
///         Length of the bytes we need to allocate to compress
///         into fixed buffer.
/// Returns:
///     (`int`):
///         maximum possible size of the output buffer needs to be.
#[pyfunction]
#[pyo3(signature = (input_len))]
#[inline]
fn get_maximum_output_size(input_len: usize) -> usize {
    lz4_flex::block::get_maximum_output_size(input_len)
}

/// Compress the input bytes using LZ4.
///
/// Args:
///     input (`bytes`):
///         Fixed set of bytes to be compressed.
///
/// Returns:
///     (`bytes`): compressed LZ4 block format.
#[pyfunction]
#[pyo3(signature = (input))]
fn compress<'py>(py: Python<'py>, input: &[u8]) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::compress(input);
    Ok(PyBytes::new(py, &output))
}

/// Compress the input bytes using LZ4 and prepend the original
/// size as a little-endian u32. This is compatible with
/// `decompress_size_prepended`.
/// Args:
///     input (`bytes`):
///         Fixed set of bytes to be compressed.
///
/// Returns:
///     (`bytes`):
///         compressed LZ4 block format with uncompressed
///         size prepended.
#[pyfunction]
#[pyo3(signature = (input))]
fn compress_prepend_size<'py>(py: Python<'py>, input: &[u8]) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::compress_prepend_size(input);
    let pybytes = PyBytes::new(py, &output);
    Ok(pybytes)
}

/// Compress all bytes of input into the output array
/// assuming size its known.    
/// Args:
///     input (`bytes`):
///         Fixed set of bytes to be compressed.
///     output (`bytesarray`):
///          Mutable buffer to hold combessed bytes.
/// Returns:
///     (`int`): size of the compressed bytes
#[pyfunction]
#[pyo3(signature = (input, output))]
fn compress_into(input: &[u8], output: PyBound<'_, PyByteArray>) -> PyResult<usize> {
    //NOTE: for possible safer practice it might be better
    //       to alloc mut vec, and return than using Pybound<'_, PyByteArray>.
    let buffer = unsafe { output.as_bytes_mut() };
    let size = lz4_flex::compress_into(input, buffer)
        .map_err(|e| LZ4BlockError::new_err(format!("{e}")))?;

    Ok(size)
}

/// Compress the input bytes using a user-provided dictionary.
/// Args:
///     input (`bytes`):
///         Fixed set of bytes to be compressed.
///     ext_dict (`bytes`):
///         A dictionary of bytes used for compression input.
/// Returns:
///    (`bytes`): decompressed bytes.
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

/// Compress input bytes using the proved dict of bytes, size is pre-appended.
///
/// Args:
///     input (`bytes`):
///         fixed set of bytes to be compressed.
///     ext_dict (`bytes`):
///         Dictionary used for compress.
/// Returns:
///     (`bytes`): compressed data.
#[pyfunction]
#[pyo3(signature = (input, ext_dict))]
fn compress_prepend_size_with_dict<'py>(
    py: Python<'py>,
    input: &[u8],
    ext_dict: &[u8],
) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::block::compress_prepend_size_with_dict(input, ext_dict);
    Ok(PyBytes::new(py, &output))
}

/// Decompress input bytes into the provided output buffer.
/// The output buffer must be preallocated with enough space
/// for the uncompressed data.
/// Args:
///     buffer (`bytes`):
///         Fixed set of bytes to be decompressed.
///     output (`bytearray`):
///         Mutable buffer to hold decompressed bytes.
/// Returns:
///     (`int`): number of bytes written to the output buffer.
#[pyfunction]
#[pyo3(signature = (input, output))]
fn decompress_into(input: &[u8], output: PyBound<'_, PyByteArray>) -> PyResult<usize> {
    let buffer = unsafe { output.as_bytes_mut() };

    let size = lz4_flex::decompress_into(input, buffer)
        .map_err(|e| LZ4BlockError::new_err(format!("{e}")))?;
    Ok(size)
}

/// Decompress the input block bytes.
/// Args:
///     input (`bytes`)
///         Fixed set of bytes to be decompressed
///     min_size (`int`):
///         Minimum possible size of uncompressed bytes
/// Returns:
///     (`bytes`): decompressed bytes.
#[pyfunction]
#[pyo3(signature = (input, min_size))]
fn decompress<'py>(
    py: Python<'py>,
    input: &[u8],
    min_size: usize,
) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::decompress(input, min_size)
        .map_err(|e| LZ4BlockError::new_err(format!("{e}")))?;
    Ok(PyBytes::new(py, &output))
}

/// Decompress input bytes that were compressed with the original
/// size prepended. Compatible with `compress_prepend_size`.
///
/// Args:
///     input (`bytes`):
///         Fixed set of bytes to be decompressed
///
// Returns:
///     (`bytes`): decompressed data.
#[pyfunction]
#[pyo3(signature = (input))]
fn decompress_size_prepended<'py>(
    py: Python<'py>,
    input: &[u8],
) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::decompress_size_prepended(input)
        .map_err(|e| LZ4BlockError::new_err(format!("{e}")))?;
    let pybytes = PyBytes::new(py, &output);
    Ok(pybytes)
}

/// Decompress input bytes using a user-provided dictionary of
/// bytes.
/// Args:
///     input (`bytes`):
///         Fixed set of bytes to be decompressed.
///     min_size (`int`):
///         Minimum possible size of uncompressed bytes.
///     ext_dict (`bytes`):
///         Dictionary used for decompression.
///
/// Returns:
///     (`bytes`): decompressed data.
#[pyfunction]
#[pyo3(signature = (input, min_size, ext_dict))]
fn decompress_with_dict<'py>(
    py: Python<'py>,
    input: &[u8],
    min_size: usize,
    ext_dict: &[u8],
) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::block::decompress_with_dict(input, min_size, ext_dict)
        .map_err(|e| LZ4BlockError::new_err(format!("{e}")))?;
    Ok(PyBytes::new(py, &output))
}

/// Decompress input bytes using a user-provided dictionary
/// of bytes, size is already pre-appended.
/// Args:
///     input (`bytes`):
///         Fixed set of bytes to be decompressed.
///     ext_dict (`bytes`):
///         Dictionary used for decompression.
///
/// Returns:
///     (`bytes`): decompressed data.
#[pyfunction]
#[pyo3(signature = (input, ext_dict))]
fn decompress_prepend_size_with_dict<'py>(
    py: Python<'py>,
    input: &[u8],
    ext_dict: &[u8],
) -> PyResult<PyBound<'py, PyBytes>> {
    let output = lz4_flex::block::decompress_size_prepended_with_dict(input, ext_dict)
        .map_err(|e| LZ4BlockError::new_err(format!("{e}")))?;
    Ok(PyBytes::new(py, &output))
}

/// rust block module handles over all structure of the compression format.
///
/// ```ignore
/// from ._safelz4_rs import _block
///
/// plaintext = b"An iterator that knows its exact length.\n        Many Iterators don\'t know how many times they will iterate, but some do."
/// output = _block.compresss(plaintext)
/// output = _block.decompress(output)
/// ```
pub(crate) fn register_block_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let block_m = PyModule::new(m.py(), "_block")?;

    // block compression
    block_m.add_function(wrap_pyfunction!(compress, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(compress_into, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(compress_prepend_size, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(compress_with_dict, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(compress_prepend_size_with_dict, &block_m)?)?;

    // block decompression
    block_m.add_function(wrap_pyfunction!(decompress, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(decompress_into, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(decompress_size_prepended, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(decompress_with_dict, &block_m)?)?;
    block_m.add_function(wrap_pyfunction!(
        decompress_prepend_size_with_dict,
        &block_m
    )?)?;

    // utility
    block_m.add_function(wrap_pyfunction!(get_maximum_output_size, &block_m)?)?;

    m.add_submodule(&block_m)?;
    Ok(())
}
