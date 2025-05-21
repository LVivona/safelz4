use std::{
    hash::Hasher,
    io::{Read, Write},
    path::PathBuf,
    sync::Arc,
};

use twox_hash::XxHash32;

use memmap2::{Mmap, MmapOptions};

use pyo3::exceptions::{PyFileExistsError, PyIOError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Bound as PyBound;

use lz4_flex::frame::{BlockMode, BlockSize, FrameDecoder, FrameEncoder, FrameInfo};

use crate::error::LZ4Exception;

const FLG_RESERVED_MASK: u8 = 0b00000010;
const FLG_VERSION_MASK: u8 = 0b11000000;
const FLG_SUPPORTED_VERSION_BITS: u8 = 0b01000000;

const FLG_INDEPENDENT_BLOCKS: u8 = 0b00100000;
const FLG_BLOCK_CHECKSUMS: u8 = 0b00010000;
const FLG_CONTENT_SIZE: u8 = 0b00001000;
const FLG_CONTENT_CHECKSUM: u8 = 0b00000100;
const FLG_DICTIONARY_ID: u8 = 0b00000001;

const BD_RESERVED_MASK: u8 = !BD_BLOCK_SIZE_MASK;
const BD_BLOCK_SIZE_MASK: u8 = 0b01110000;
const BD_BLOCK_SIZE_MASK_RSHIFT: u8 = 4;

const BLOCK_UNCOMPRESSED_SIZE_BIT: u32 = 0x80000000;

const LZ4F_MAGIC_NUMBER: u32 = 0x184D2204;
const LZ4F_LEGACY_MAGIC_NUMBER: u32 = 0x184C2102;
const LZ4F_SKIPPABLE_MAGIC_RANGE: std::ops::RangeInclusive<u32> = 0x184D2A50..=0x184D2A5F;

const MAGIC_NUMBER_SIZE: usize = 4;
const MIN_FRAME_INFO_SIZE: usize = 7;
const MAX_FRAME_INFO_SIZE: usize = 19;
const BLOCK_INFO_SIZE: usize = 4;

///Block mode for frame compression.
///
///Attributes:
///    Independent: Independent block mode.
///    Linked: Linked block mode.
#[pyclass(eq, eq_int, name = "BlockMode")]
#[derive(Default, Debug, Eq, PartialEq, Clone)]
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

/// Block size for frame compression.
/// Attributes:
///     Auto: Will detect optimal frame size based on the size of the first write call.
///     Max64KB: The default block size (64KB).
///     Max256KB: 256KB block size.
///     Max1MB: 1MB block size.
///     Max4MB: 4MB block size.
///     Max8MB: 8MB block size.
#[pyclass(name = "BlockSize")]
#[derive(Default, Debug, Clone, PartialEq, Eq)]
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
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[pyclass(name = "FrameInfo", eq)]
struct PyFramInfo {
    /// If set, includes the total uncompressed size of data in the frame.
    pub content_size: Option<u64>,
    /// The maximum uncompressed size of each data block.
    pub block_size: PyBlockSize,
    /// The block mode.
    pub block_mode: PyBlockMode,
    /// The identifier for the dictionary that must be used to correctly decode data.
    /// The compressor and the decompressor must use exactly the same dictionary.
    ///
    /// Note that this is currently unsupported and for this reason it's not pub.
    #[allow(dead_code)]
    pub(crate) dict_id: Option<u32>,

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
    #[pyo3(signature = (block_size, block_mode, block_checksums = None, dict_id = None, content_checksum = None, content_size = None, legacy_frame = None))]
    fn new(
        block_size: PyBlockSize,
        block_mode: PyBlockMode,
        block_checksums: Option<bool>,
        dict_id: Option<u32>,
        content_checksum: Option<bool>,
        content_size: Option<u64>,
        legacy_frame: Option<bool>,
    ) -> Self {
        Self {
            block_mode,
            block_size,
            content_size,
            dict_id,
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

    /// Since the header size is dynamic we can read the size of the header before
    /// we build our frame class.
    #[staticmethod]
    fn read_header_size(input: &[u8]) -> PyResult<usize> {
        if input.len() < 5 {
            return Err(LZ4Exception::new_err("Too small to read magic number."));
        }

        let mut required = MIN_FRAME_INFO_SIZE;
        let magic_num = u32::from_le_bytes(input[0..4].try_into().unwrap());
        if magic_num == LZ4F_LEGACY_MAGIC_NUMBER {
            return Ok(MAGIC_NUMBER_SIZE);
        }

        if input.len() < required {
            return Ok(required);
        }

        if LZ4F_SKIPPABLE_MAGIC_RANGE.contains(&magic_num) {
            return Ok(8);
        }
        if magic_num != LZ4F_MAGIC_NUMBER {
            return Err(LZ4Exception::new_err("Unexpected magic number."));
        }

        if input[4] & FLG_CONTENT_SIZE != 0 {
            required += 8;
        }
        if input[4] & FLG_DICTIONARY_ID != 0 {
            required += 4
        }
        Ok(required)
    }

    #[staticmethod]
    fn read_header_info(mut input: &[u8]) -> PyResult<PyFramInfo> {
        let original_input = input;
        // 4 byte Magic
        let magic_num = {
            let mut buffer = [0u8; 4];
            input.read_exact(&mut buffer)?;
            u32::from_le_bytes(buffer)
        };
        if magic_num == LZ4F_LEGACY_MAGIC_NUMBER {
            return Ok(PyFramInfo {
                block_size: PyBlockSize::Max8MB,
                legacy_frame: true,
                ..Default::default()
            });
        }
        if LZ4F_SKIPPABLE_MAGIC_RANGE.contains(&magic_num) {
            let mut buffer = [0u8; 4];
            input.read_exact(&mut buffer)?;
            let user_data_len = u32::from_le_bytes(buffer);
            return Err(LZ4Exception::new_err(format!(
                "Within skipable frames range {user_data_len:?}."
            )));
        }
        if magic_num != LZ4F_MAGIC_NUMBER {
            return Err(LZ4Exception::new_err(format!(
                "Wrong magic number, expected 0x{LZ4F_MAGIC_NUMBER:x}."
            )));
        }

        // fixed size section
        let [flg_byte, bd_byte] = {
            let mut buffer = [0u8, 0];
            input.read_exact(&mut buffer)?;
            buffer
        };

        if flg_byte & FLG_VERSION_MASK != FLG_SUPPORTED_VERSION_BITS {
            // version is always 01
            // return Err(Error::UnsupportedVersion(flg_byte & FLG_VERSION_MASK));
            return Err(LZ4Exception::new_err("unsupported version"));
        }

        if flg_byte & FLG_RESERVED_MASK != 0 || bd_byte & BD_RESERVED_MASK != 0 {
            // return Err(Error::ReservedBitsSet);
            return Err(LZ4Exception::new_err(
                "flag bytes reserved bit are not supported",
            ));
        }

        let block_mode = if flg_byte & FLG_INDEPENDENT_BLOCKS != 0 {
            PyBlockMode::Independent
        } else {
            PyBlockMode::Linked
        };
        let content_checksum = flg_byte & FLG_CONTENT_CHECKSUM != 0;
        let block_checksums = flg_byte & FLG_BLOCK_CHECKSUMS != 0;

        let block_size = match (bd_byte & BD_BLOCK_SIZE_MASK) >> BD_BLOCK_SIZE_MASK_RSHIFT {
            i @ 0..=3 => {
                return Err(LZ4Exception::new_err(format!(
                    "unsuppored block size number {i:?}"
                )))
            }
            4 => PyBlockSize::Max64KB,
            5 => PyBlockSize::Max256KB,
            6 => PyBlockSize::Max1MB,
            7 => PyBlockSize::Max4MB,
            8 => PyBlockSize::Max8MB,
            _ => unreachable!(),
        };

        // var len section
        let mut content_size = None;
        if flg_byte & FLG_CONTENT_SIZE != 0 {
            let mut buffer = [0u8; 8];
            input.read_exact(&mut buffer).unwrap();
            content_size = Some(u64::from_le_bytes(buffer));
        }

        let mut dict_id = None;
        if flg_byte & FLG_DICTIONARY_ID != 0 {
            let mut buffer = [0u8; 4];
            input.read_exact(&mut buffer)?;
            dict_id = Some(u32::from_le_bytes(buffer));
        }

        // 1 byte header checksum
        let expected_checksum = {
            let mut buffer = [0u8; 1];
            input.read_exact(&mut buffer)?;
            buffer[0]
        };
        let mut hasher = XxHash32::with_seed(0);
        hasher.write(&original_input[4..original_input.len() - input.len() - 1]);
        let header_hash = (hasher.finish() >> 8) as u8;
        if header_hash != expected_checksum {
            return Err(LZ4Exception::new_err(format!(
                "Expected checksum {expected_checksum:?}, got {header_hash:?}"
            )));
        }

        Ok(PyFramInfo {
            content_size,
            block_size,
            block_mode,
            dict_id,
            block_checksums,
            content_checksum,
            legacy_frame: false,
        })
    }

    #[getter]
    fn get_block_checksums(&self) -> PyResult<bool> {
        Ok(self.block_checksums)
    }

    #[getter]
    fn get_block_mode(&self) -> PyResult<PyBlockMode> {
        Ok(self.block_mode.clone())
    }

    #[getter]
    fn get_block_size(&self) -> PyResult<PyBlockSize> {
        Ok(self.block_size.clone())
    }

    #[getter]
    fn get_content_size(&self) -> PyResult<Option<u64>> {
        Ok(self.content_size)
    }

    #[getter]
    fn get_content_sum(&self) -> PyResult<bool> {
        Ok(self.content_checksum)
    }

    #[setter(block_mode)]
    fn set_block_mode(&mut self, value: PyBlockMode) -> PyResult<()> {
        self.block_mode = value;
        Ok(())
    }

    #[setter(block_size)]
    fn set_block_size(&mut self, value: PyBlockSize) -> PyResult<()> {
        self.block_size = value;
        Ok(())
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
fn compress<'py>(py: Python<'py>, input: &[u8]) -> PyResult<PyBound<'py, PyBytes>> {
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
fn compress_file(filename: PathBuf, input: &[u8]) -> PyResult<()> {
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
fn compress_file_with_info(
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
fn compress_with_info<'py>(
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
///         Typically obtained from a prior call to an `compress`, `compress_with_info` or read from
///         a compressed file `compress_file`, or `compress_file_with_info`.
/// Returns:
///     `bytes`:
///         The decompressed (original) representation of the input bytes.
#[pyfunction]
#[pyo3(signature = (input))]
fn decompress<'py>(py: Python<'py>, input: &[u8]) -> PyResult<PyBound<'py, PyBytes>> {
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
fn decompress_file(py: Python<'_>, filename: PathBuf) -> PyResult<PyBound<'_, PyBytes>> {
    let file = std::fs::File::open(&filename)
        .map_err(|_| PyFileExistsError::new_err(format!("{filename:?} already exist.")))?;
    let rdr = std::io::BufReader::new(file);
    let mut decoder = FrameDecoder::new(rdr);

    let mut buffer = Vec::new();
    decoder.read_to_end(&mut buffer)?;
    Ok(PyBytes::new(py, &buffer))
}

struct Open {
    /// Atomic read only access to file memory.
    storage: Arc<Mmap>,
    /// Frame file type info
    info: PyFramInfo,
    /// offset **used for release build**
    #[allow(dead_code)]
    offset: usize,
}

impl Open {
    /// instaniate the mmap of ReadOnly file.
    pub(crate) fn new(filename: PathBuf) -> PyResult<Self> {
        let file = std::fs::File::open(filename)?;

        let storage = Arc::new(unsafe { MmapOptions::new().map_copy_read_only(&file)? });
        let info = PyFramInfo::read_header_info(&storage)?;
        let offset = PyFramInfo::read_header_size(&storage)?;
        Ok(Self {
            storage,
            info,
            offset,
        })
    }

    /// helper of [`open_frame`] to access the FrameInfo of frame file.
    pub(crate) fn info(&self) -> PyFramInfo {
        self.info.clone()
    }

    /// deompression output size for allocation of memmory
    pub(crate) fn content_size(&self) -> Option<u64> {
        self.info.content_size
    }

    pub(crate) fn block_size(&self) -> PyBlockSize {
        self.info.block_size.clone()
    }

    /// decompress the the bytes within the Read only [`Mmap`]
    pub(crate) fn decompress<'py>(&self, py: Python<'py>) -> PyResult<PyBound<'py, PyBytes>> {
        decompress(py, &self.storage)
    }
}

/// Context manager that allows us to decompresses a buffer of bytes using thex LZ4 frame format.
///
/// Example:
/// ```ignore
/// output = None
/// with open_frame("datafile") as f:
///     output = f.decompress()
///
/// print(output)
/// ```
///
#[pyclass]
#[allow(non_camel_case_types)]
struct open_frame {
    inner: Option<Open>,
}

impl open_frame {
    /// helper that reduces the syntax in case of None open_frame
    pub(crate) fn inner(&self) -> PyResult<&Open> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| LZ4Exception::new_err("File is closed".to_string()))?;
        Ok(inner)
    }
}

#[pymethods]
impl open_frame {
    /// Initialize the open_frame context manager with a filename.
    #[new]
    #[pyo3(signature = (filename))]
    fn new(filename: PathBuf) -> PyResult<Self> {
        let inner = Some(Open::new(filename)?);
        Ok(Self { inner })
    }

    /// Return the frameinfo of the compression file
    /// Returns:
    ///     `FrameInfo`:
    ///         The freeform FrameInfo.
    pub fn info(&self) -> PyResult<PyFramInfo> {
        Ok(self.inner()?.info())
    }

    /// Return the content size of the frame
    /// Returns:
    ///     `int`: size of each.
    pub fn content_size(&self) -> PyResult<Option<u64>> {
        Ok(self.inner()?.content_size())
    }

    /// Returns the decompress block size of each individual block
    /// Returns
    ///     `BlockSize`: size for frame compression.
    pub fn block_size(&self) -> PyResult<PyBlockSize> {
        Ok(self.inner()?.block_size())
    }

    /// Decompress the whole frame file
    ///
    /// Returns:
    ///     `bytes`:
    ///         The decompressed (original) representation of the bytes within the file.
    ///
    pub fn decompress<'py>(&self, py: Python<'py>) -> PyResult<PyBound<'py, PyBytes>> {
        self.inner()?.decompress(py)
    }

    /// Enter the context manager and return self.
    pub fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Exit the context manager and clean up resources.
    pub fn __exit__(&mut self, _exc_type: PyObject, _exc_value: PyObject, _traceback: PyObject) {
        self.inner = None;
    }
}

/// register frame module handles which handles Frame de/compression of frames.
///
/// ```ignore
/// from .safelz4_rs import _frame
///
/// plaintext = b"eeeeeeee Hello world this is an example of plaintext being compressed eeeeeeeeeeeeeee"
/// output = _frame.compress(plaintext)
/// output = _frame.decompress(output)
/// ```
pub(crate) fn register_frame_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let frame_m = PyModule::new(m.py(), "_frame")?;

    // function
    frame_m.add_function(wrap_pyfunction!(compress, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(compress_file, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(compress_file_with_info, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(compress_with_info, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(decompress_file, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(decompress, &frame_m)?)?;

    // class objects
    frame_m.add_class::<PyFramInfo>()?;
    frame_m.add_class::<PyBlockMode>()?;
    frame_m.add_class::<PyBlockSize>()?;
    frame_m.add_class::<open_frame>()?;

    // const number for reading frame blocks
    frame_m.add("FLG_RESERVED_MASK", FLG_RESERVED_MASK)?;
    frame_m.add("FLG_VERSION_MASK", FLG_VERSION_MASK)?;
    frame_m.add("FLG_SUPPORTED_VERSION_BITS", FLG_SUPPORTED_VERSION_BITS)?;

    frame_m.add("FLG_INDEPENDENT_BLOCKS", FLG_INDEPENDENT_BLOCKS)?;
    frame_m.add("FLG_BLOCK_CHECKSUMS", FLG_BLOCK_CHECKSUMS)?;
    frame_m.add("FLG_CONTENT_SIZE", FLG_CONTENT_SIZE)?;
    frame_m.add("FLG_CONTENT_CHECKSUM", FLG_CONTENT_CHECKSUM)?;
    frame_m.add("FLG_DICTIONARY_ID", FLG_DICTIONARY_ID)?;

    frame_m.add("BD_RESERVED_MASK", BD_RESERVED_MASK)?;
    frame_m.add("BD_BLOCK_SIZE_MASK", BD_BLOCK_SIZE_MASK)?;
    frame_m.add("BD_BLOCK_SIZE_MASK_RSHIFT", BD_BLOCK_SIZE_MASK_RSHIFT)?;

    frame_m.add("BLOCK_UNCOMPRESSED_SIZE_BIT", BLOCK_UNCOMPRESSED_SIZE_BIT)?;

    frame_m.add("LZ4F_MAGIC_NUMBER", LZ4F_MAGIC_NUMBER)?;
    frame_m.add("LZ4F_LEGACY_MAGIC_NUMBER", LZ4F_LEGACY_MAGIC_NUMBER)?;

    frame_m.add("MAGIC_NUMBER_SIZE", MAGIC_NUMBER_SIZE)?;
    frame_m.add("MIN_FRAME_INFO_SIZE", MIN_FRAME_INFO_SIZE)?;
    frame_m.add("MAX_FRAME_INFO_SIZE", MAX_FRAME_INFO_SIZE)?;
    frame_m.add("BLOCK_INFO_SIZE", BLOCK_INFO_SIZE)?;

    m.add_submodule(&frame_m)?;
    Ok(())
}
