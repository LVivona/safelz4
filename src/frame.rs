use std::{
    io::{Read, Write},
    path::PathBuf,
};

use pyo3::exceptions::{PyFileExistsError, PyIOError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Bound as PyBound;

use lz4_flex::frame::{BlockMode, BlockSize, FrameDecoder, FrameEncoder, FrameInfo};

///Block mode for frame compression.
///
///Attributes:
///    Independent: Independent block mode.
///    Linked: Linked block mode.
#[pyclass(eq, eq_int, name = "BlockMode")]
#[derive(Default, Debug, PartialEq, Clone)]
enum PyBlockMode {
    #[default]
    Independent,
    Linked,
}

impl From<PyBlockMode> for BlockMode {
    fn from(val: PyBlockMode) -> Self {
        match val {
            PyBlockMode::Independent => BlockMode::Independent,
            PyBlockMode::Linked => BlockMode::Linked,
        }
    }
}

///    Block size for frame compression.
/// Attributes:
///     Auto: Will detect optimal frame size based on the size of the first write call.
///     Max64KB: The default block size (64KB).
///     Max256KB: 256KB block size.
///     Max1MB: 1MB block size.
///     Max4MB: 4MB block size.
///     Max8MB: 8MB block size.
#[pyclass(name = "BlockSize")]
#[derive(Default, Debug, Clone)]
enum PyBlockSize {
    /// Will detect optimal frame size based on the size of the first write call
    #[default]
    Auto = 0,
    /// The default block size.
    Max64KB = 4,
    /// 256KB block size.
    Max256KB = 5,
    /// 1MB block size.
    Max1MB = 6,
    /// 4MB block size.
    Max4MB = 7,
    /// 8MB block size.
    Max8MB = 8,
}

impl From<PyBlockSize> for BlockSize {
    fn from(val: PyBlockSize) -> Self {
        match val {
            PyBlockSize::Auto => BlockSize::Auto,
            PyBlockSize::Max64KB => BlockSize::Max64KB,
            PyBlockSize::Max256KB => BlockSize::Max256KB,
            PyBlockSize::Max1MB => BlockSize::Max1MB,
            PyBlockSize::Max4MB => BlockSize::Max4MB,
            PyBlockSize::Max8MB => BlockSize::Max8MB,
        }
    }
}

/// Information about a compression frame.
/// Attributes:
///     content_size: If set, includes the total uncompressed size of data in the frame.
///     block_size: The maximum uncompressed size of each data block.
///     block_mode: The block mode.
///     block_checksums: If set, includes a checksum for each data block in the frame.
///     content_checksum: If set, includes a content checksum to verify that the full frame contents have been decoded correctly.
///     legacy_frame: If set, use the legacy frame format.
#[derive(Default, Debug, Clone)]
#[pyclass(name = "FrameInfo", subclass)]
struct PyFramInfo {
    /// If set, includes the total uncompressed size of data in the frame.
    pub content_size: Option<u64>,
    /// The maximum uncompressed size of each data block.
    pub block_size: PyBlockSize,
    /// The block mode.
    pub block_mode: PyBlockMode,
    /// If set, includes a checksum for each data block in the frame.
    pub block_checksums: bool,
    /// If set, includes a content checksum to verify that the full frame contents have been
    /// decoded correctly.
    pub content_checksum: bool,
    /// If set, use the legacy frame format
    pub legacy_frame: bool,
}

impl From<PyFramInfo> for FrameInfo {
    fn from(val: PyFramInfo) -> Self {
        FrameInfo::new()
            .block_checksums(val.block_checksums)
            .block_mode(val.block_mode.clone().into())
            .block_size(val.block_size.clone().into())
            .content_checksum(val.content_checksum)
            .content_size(val.content_size)
            .legacy_frame(val.legacy_frame)
    }
}

#[pymethods]
impl PyFramInfo {
    #[new]
    #[pyo3(signature = (block_size, block_mode, block_checksums = None, content_checksum = None, content_size = None, legacy_frame = None))]
    fn new(
        block_size: PyBlockSize,
        block_mode: PyBlockMode,
        block_checksums: Option<bool>,
        content_checksum: Option<bool>,
        content_size: Option<u64>,
        legacy_frame: Option<bool>,
    ) -> Self {
        Self {
            block_mode,
            block_size,
            content_size,
            block_checksums: block_checksums.unwrap_or_default(),
            content_checksum: content_checksum.unwrap_or_default(),
            legacy_frame: legacy_frame.unwrap_or_default(),
        }
    }

    #[staticmethod]
    fn default() -> Self {
        Self {
            ..Default::default()
        }
    }

    #[getter]
    fn get_block_checksums(&self) -> PyResult<bool> {
        Ok(self.block_checksums)
    }

    #[getter]
    fn get_block_mode<'py>(&self, py: Python<'py>) -> PyResult<PyBound<'py, PyBlockMode>> {
        self.block_mode.clone().into_pyobject(py)
    }

    #[getter]
    fn get_content_size(&self) -> PyResult<Option<u64>> {
        Ok(self.content_size)
    }

    #[getter]
    fn get_content_sum(&self) -> PyResult<bool> {
        Ok(self.content_checksum)
    }

    #[setter(block_checksums)]
    fn set_block_checksums(&mut self, value: bool) -> PyResult<()> {
        self.block_checksums = value;
        Ok(())
    }

    #[setter(content_size)]
    fn set_content_size(&mut self, value: u64) -> PyResult<()> {
        self.content_size = Some(value);
        Ok(())
    }

    #[setter(content_checksum)]
    fn set_content_checksum(&mut self, value: bool) -> PyResult<()> {
        self.content_checksum = value;
        Ok(())
    }

    #[setter(legacy_frame)]
    fn set_legacy_frame(&mut self, value: bool) -> PyResult<()> {
        self.legacy_frame = value;
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "FrameInfo(content_size={:?}, block_checksum={:?}, block_size={:?}, block_mode={:?}, content_checksum={:?}, legacy_frame={:?})",
            self.content_size, self.block_checksums, self.block_size, self.block_mode, self.content_checksum, self.legacy_frame
        )
    }

    fn __str__(&self) -> String {
        format!(
            "FrameInfo(content_size={:?}, block_checksum={:?}, block_size={:?}, block_mode={:?}, content_checksum={:?}, legacy_frame={:?})",
            self.content_size, self.block_checksums, self.block_size, self.block_mode, self.content_checksum, self.legacy_frame
        )
    }
}

/// Compresses a buffer of LZ4-compressed bytes using the LZ4 frame format.
///
/// Args:
///     input (`bytes`):
///         An arbitrary byte buffer to be compressed.
///
/// Returns:
///     `bytes`:
///         The LZ4 frame-compressed representation of the input bytes.
#[pyfunction]
#[pyo3(signature = (input))]
fn deflate<'py>(py: Python<'py>, input: &[u8]) -> PyResult<PyBound<'py, PyBytes>> {
    let wtr = Vec::with_capacity(input.len());

    let mut encoder = FrameEncoder::new(wtr);
    encoder
        .write(input)
        .map_err(|_| PyIOError::new_err("Faild to write to buffer."))?;
    encoder.flush()?;

    Ok(PyBytes::new(
        py,
        &encoder
            .finish()
            .map_err(|e| PyIOError::new_err(format!("Failed to finish LZ4 compression: {}", e)))?,
    ))
}

/// Compresses a buffer of bytes into a file using using the LZ4 frame format.
/// Args:
///     filename (`str` or `os.PathLike`):
///         The filename we are saving into.
///     input (`bytes`):
///         un-compressed representation of the input bytes.
/// Returns:
///     `None`
#[pyfunction]
#[pyo3(signature = (filename, input))]
fn deflate_file(filename: PathBuf, input: &[u8]) -> PyResult<()> {
    let file = std::fs::File::create(&filename)
        .map_err(|_| PyFileExistsError::new_err(format!("{filename:?} already exist.")))?;
    let vec = std::io::BufWriter::new(file);
    let mut encoder = FrameEncoder::new(vec);

    // write bytes into compressed format.
    encoder.write_all(input)?;

    // flush out buffer.
    encoder
        .flush()
        .map_err(|e| PyIOError::new_err(format!("Failed to finish LZ4 compression: {}", e)))
}

/// Compresses a buffer of bytes into a file using using the LZ4 frame format, with more control on Frame.
///
/// Args:
///    filename (`str`, or `os.PathLike`):
///        The filename we are saving into.
///    input (`bytes`):
///        fixed set of bytes to be compressed.
///    info (`FrameInfo, *optional*, defaults to `None``):
///        The metadata for de/compressing with lz4 frame format.
///
/// Returns:
///    `None`
#[pyfunction]
#[pyo3(signature = (filename, input, info = None))]
fn deflate_file_with_info(
    filename: PathBuf,
    input: &[u8],
    info: Option<PyFramInfo>,
) -> PyResult<()> {
    let file = std::fs::File::create(&filename)
        .map_err(|_| PyFileExistsError::new_err(format!("{filename:?} already exist.")))?;
    let wtr = std::io::BufWriter::new(file);

    let info_f: FrameInfo = info.unwrap_or_default().into();

    let mut encoder = FrameEncoder::with_frame_info(info_f, wtr);
    encoder.write_all(input)?;
    encoder
        .flush()
        .map_err(|e| PyIOError::new_err(format!("Failed to finish LZ4 compression: {}", e)))
}

/// Compresses a buffer of bytes into byte buffer using using the LZ4 frame format, with more control on Frame.
/// Args:
///     input (`bytes`):
///         fixed set of bytes to be compressed.
///     info (`FrameInfo, *optional*, defaults to `None``):
///         The metadata for de/compressing with lz4 frame format.
/// Returns:
///     `bytes`:
///         The LZ4 frame-compressed representation of the input bytes.
#[pyfunction]
#[pyo3(signature = (input, info = None))]
fn deflate_with_info<'py>(
    py: Python<'py>,
    input: &[u8],
    info: Option<PyFramInfo>,
) -> PyResult<PyBound<'py, PyBytes>> {
    let wtr = Vec::with_capacity(input.len());

    let info_f: FrameInfo = info.unwrap_or_default().into();

    let mut encoder = FrameEncoder::with_frame_info(info_f, wtr);
    encoder.write_all(input)?;

    let output = encoder
        .finish()
        .map_err(|e| PyIOError::new_err(format!("Failed to finish LZ4 compression: {}", e)))?;

    Ok(PyBytes::new(py, &output))
}
/// Decompresses a buffer of bytes using thex LZ4 frame format.
/// Args:
///     input (`bytes`):
///         A byte containing LZ4-compressed data (in frame format).
///         Typically obtained from a prior call to an `deflate`, `deflate_with_info` or read from
///         a compressed file `deflate_file`, or `deflate_file_with_info`.
/// Returns:
///     `bytes`:
///         The decompressed (original) representation of the input bytes.
#[pyfunction]
#[pyo3(signature = (input))]
fn enflate<'py>(py: Python<'py>, input: &[u8]) -> PyResult<PyBound<'py, PyBytes>> {
    let mut decoder = FrameDecoder::new(input);
    let mut buffer = Vec::new();
    decoder.read_to_end(&mut buffer)?;
    Ok(PyBytes::new(py, &buffer))
}

/// Decompresses a buffer of bytes into a file using thex LZ4 frame format.
///
/// Args:
///    filename (`str` or `os.PathLike`):
///        The filename we are loading from.
///
/// Returns:
///    `bytes`:
///        The decompressed (original) representation of the input bytes.
#[pyfunction]
#[pyo3(signature = (filename))]
fn enflate_file(py: Python<'_>, filename: PathBuf) -> PyResult<PyBound<'_, PyBytes>> {
    let file = std::fs::File::open(&filename)
        .map_err(|_| PyFileExistsError::new_err(format!("{filename:?} already exist.")))?;
    let rdr = std::io::BufReader::new(file);
    let mut decoder = FrameDecoder::new(rdr);

    let mut buffer = Vec::new();
    decoder.read_to_end(&mut buffer)?;
    Ok(PyBytes::new(py, &buffer))
}

/// register frame module handles which handles Frame de/compression of frames.
///
/// ```ignore
/// from .safelz4_rs import _frame
///
/// plaintext = b"eeeeeeee Hello world this is an example of plaintext being compressed eeeeeeeeeeeeeee"
/// output = _frame.deflate(plaintext)
/// output = _frame.enflate(output)
/// ```
pub(crate) fn register_frame_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let frame_m = PyModule::new(m.py(), "_frame")?;

    frame_m.add_function(wrap_pyfunction!(deflate, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(deflate_file, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(deflate_file_with_info, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(deflate_with_info, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(enflate_file, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(enflate, &frame_m)?)?;

    frame_m.add_class::<PyFramInfo>()?;
    frame_m.add_class::<PyBlockMode>()?;
    frame_m.add_class::<PyBlockSize>()?;

    m.add_submodule(&frame_m)?;
    Ok(())
}
