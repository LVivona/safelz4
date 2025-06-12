use std::{
    fs::File,
    hash::Hasher,
    io::{BufWriter, Read, Write},
    path::PathBuf,
    sync::Arc,
};

use twox_hash::XxHash32;

use memmap2::{Mmap, MmapOptions};

use pyo3::exceptions::{PyFileExistsError, PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Bound as PyBound;

use lz4_flex::frame::{BlockMode, BlockSize, FrameDecoder, FrameEncoder, FrameInfo};

use crate::error::{
    CompressionError, DecompressionError, HeaderError, LZ4BlockError, LZ4Exception, ReadError,
};

const WINDOW_SIZE: usize = 65536;

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
#[derive(Default, Debug, Eq, PartialEq, Clone, Copy)]
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

impl From<BlockMode> for PyBlockMode {
    fn from(val: BlockMode) -> Self {
        match val {
            BlockMode::Independent => PyBlockMode::Independent,
            BlockMode::Linked => PyBlockMode::Linked,
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
#[pyclass(eq, eq_int, name = "BlockSize")]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
enum PyBlockSize {
    /// Will detect optimal frame size based on the size of the first write call.
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

#[pymethods]
impl PyBlockSize {
    /// Try to find optimal size based on passed buffer length.
    #[staticmethod]
    pub fn from_buf_length(buf_len: usize) -> Self {
        let mut blocksize = PyBlockSize::Max4MB;

        for candidate in [PyBlockSize::Max256KB, PyBlockSize::Max64KB] {
            if buf_len > candidate.get_size().unwrap() {
                return blocksize;
            }
            blocksize = candidate;
        }
        PyBlockSize::Max64KB
    }

    /// Return the size in bytes
    pub fn get_size(&self) -> PyResult<usize> {
        match self {
            PyBlockSize::Auto => Err(LZ4Exception::new_err(
                "Auto does not have a predetermined size",
            )),
            PyBlockSize::Max64KB => Ok(64 * 1024),
            PyBlockSize::Max256KB => Ok(256 * 1024),
            PyBlockSize::Max1MB => Ok(1024 * 1024),
            PyBlockSize::Max4MB => Ok(4 * 1024 * 1024),
            PyBlockSize::Max8MB => Ok(8 * 1024 * 1024),
        }
    }
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

impl From<BlockSize> for PyBlockSize {
    fn from(val: BlockSize) -> Self {
        match val {
            BlockSize::Auto => PyBlockSize::Auto,
            BlockSize::Max64KB => PyBlockSize::Max64KB,
            BlockSize::Max256KB => PyBlockSize::Max256KB,
            BlockSize::Max1MB => PyBlockSize::Max1MB,
            BlockSize::Max4MB => PyBlockSize::Max4MB,
            BlockSize::Max8MB => PyBlockSize::Max8MB,
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
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
#[pyclass(name = "FrameInfo", eq)]
struct PyFrameInfo {
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

impl From<FrameInfo> for PyFrameInfo {
    fn from(val: FrameInfo) -> Self {
        PyFrameInfo::new(
            val.block_size.into(),
            val.block_mode.into(),
            Some(val.block_checksums),
            None,
            Some(val.content_checksum),
            val.content_size,
            Some(val.legacy_frame),
        )
    }
}

impl From<PyFrameInfo> for FrameInfo {
    fn from(val: PyFrameInfo) -> Self {
        FrameInfo::new()
            .block_checksums(val.block_checksums)
            .block_mode(val.block_mode.into())
            .block_size(val.block_size.into())
            .content_checksum(val.content_checksum)
            .content_size(val.content_size)
            .legacy_frame(val.legacy_frame)
    }
}

#[pymethods]
impl PyFrameInfo {
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

    /// Build a default `FrameInfo` class.
    /// Returns:
    ///     (`FrameInfo`): default object.
    #[staticmethod]
    fn default() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// Read the size of the frame header info.
    ///
    /// Since the header size is dynamic we can read the size of the header before
    /// we build our frame class.
    ///
    /// Expected Output sizes:
    ///     4 - legacy frame.
    ///     7 - length is less then MIN_FRAME_INFO_SIZE.
    ///     8 - magic Number is in Skippable range.
    ///     8 - only dict_id.
    ///     12- only content size.
    ///     16- both content size and dict_id.
    ///
    /// Since the header size is dynamic we can read the size of the header before
    /// we build our frame class.
    #[staticmethod]
    fn read_header_size(input: &[u8]) -> PyResult<usize> {
        let length = input.len();
        if length < 4 {
            return Err(HeaderError::new_err("Too small to read magic number."));
        }

        let array = [input[0], input[1], input[2], input[3]];

        let mut required = MIN_FRAME_INFO_SIZE;
        let magic_num = u32::from_le_bytes(array);
        if magic_num == LZ4F_LEGACY_MAGIC_NUMBER {
            return Ok(MAGIC_NUMBER_SIZE);
        }

        if length < required {
            return Ok(required);
        }

        if LZ4F_SKIPPABLE_MAGIC_RANGE.contains(&magic_num) {
            return Ok(8);
        }
        if magic_num != LZ4F_MAGIC_NUMBER {
            return Err(HeaderError::new_err("Unexpected magic number."));
        }

        if input[4] & FLG_CONTENT_SIZE != 0 {
            required += 8;
        }
        if input[4] & FLG_DICTIONARY_ID != 0 {
            required += 4
        }
        Ok(required)
    }

    /// Read bytes info to construct frame header.
    #[staticmethod]
    fn read_header_info(mut input: &[u8]) -> PyResult<PyFrameInfo> {
        let original_input = input;
        let length = input.len();
        // header must be big enough to index the buffer (4 byte)
        if length < MAGIC_NUMBER_SIZE {
            return Err(HeaderError::new_err("Header is too small."));
        }

        let magic_num = {
            let mut buffer = [0u8; 4];
            input.read_exact(&mut buffer)?;
            u32::from_le_bytes(buffer)
        };

        // check if legacy magic number.
        if magic_num == LZ4F_LEGACY_MAGIC_NUMBER {
            return Ok(PyFrameInfo {
                block_size: PyBlockSize::Max8MB,
                legacy_frame: true,
                ..Default::default()
            });
        }

        // if within reange of LZ4F next for bytes
        if LZ4F_SKIPPABLE_MAGIC_RANGE.contains(&magic_num) {
            let mut buffer = [0u8; 4];
            input.read_exact(&mut buffer)?;
            let user_data_len = u32::from_le_bytes(buffer);
            return Err(HeaderError::new_err(format!(
                "Within skipable frames range {user_data_len:?}."
            )));
        }

        // compare magic number.
        if magic_num != LZ4F_MAGIC_NUMBER {
            return Err(HeaderError::new_err(format!(
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
            // version is always 01;
            return Err(HeaderError::new_err("unsupported version"));
        }

        if flg_byte & FLG_RESERVED_MASK != 0 || bd_byte & BD_RESERVED_MASK != 0 {
            return Err(HeaderError::new_err(
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
                return Err(HeaderError::new_err(format!(
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
        hasher.write(&original_input[MAGIC_NUMBER_SIZE..length - input.len() - 1]);
        let header_hash = (hasher.finish() >> 8) as u8;
        if header_hash != expected_checksum {
            return Err(HeaderError::new_err(format!(
                "Expected checksum {expected_checksum:?}, got {header_hash:?}"
            )));
        }

        Ok(PyFrameInfo {
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
        Ok(self.block_mode)
    }

    #[getter]
    fn get_block_size(&self) -> PyResult<PyBlockSize> {
        Ok(self.block_size)
    }

    #[getter]
    fn get_content_size(&self) -> PyResult<Option<u64>> {
        Ok(self.content_size)
    }

    #[getter]
    fn get_content_checksum(&self) -> PyResult<bool> {
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
///     (`bytes`):
///         the LZ4 frame-compressed representation of the input bytes.
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
        &encoder.finish().map_err(|e| {
            CompressionError::new_err(format!("Failed to finish LZ4 compression: {}", e))
        })?,
    ))
}

/// Compresses a buffer of bytes into a file using using the LZ4 frame format.
/// Args:
///     filename (`str` or `os.PathLike`):
///         The filename we are saving into.
///     input (`bytes`):
///         un-compressed representation of the input bytes.
/// Returns:
///     (`None`)
#[pyfunction]
#[pyo3(signature = (filename, input))]
fn compress_into_file(filename: PathBuf, input: &[u8]) -> PyResult<()> {
    let file = std::fs::File::create(&filename)
        .map_err(|_| PyFileExistsError::new_err(format!("{filename:?} already exist.")))?;
    let vec = std::io::BufWriter::new(file);
    let mut encoder = FrameEncoder::new(vec);

    // write bytes into compressed format.
    encoder.write_all(input)?;

    // flush out buffer.
    encoder
        .flush()
        .map_err(|e| CompressionError::new_err(format!("Failed to finish LZ4 compression: {}", e)))
}

/// Compresses a buffer of bytes into a file using using the LZ4 frame format,
/// with more control on Block Linkage.
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
///    (`None`)
#[pyfunction]
#[pyo3(signature = (filename, input, info = None))]
fn compress_into_file_with_info(
    filename: PathBuf,
    input: &[u8],
    info: Option<PyFrameInfo>,
) -> PyResult<()> {
    let file = std::fs::File::create(&filename)
        .map_err(|_| PyFileExistsError::new_err(format!("{filename:?} already exist.")))?;
    let wtr = std::io::BufWriter::new(file);

    let info_f: FrameInfo = info.unwrap_or_default().into();

    let mut encoder = FrameEncoder::with_frame_info(info_f, wtr);
    encoder.write_all(input)?;
    encoder
        .flush()
        .map_err(|e| CompressionError::new_err(format!("Failed to finish LZ4 compression: {}.", e)))
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
    info: Option<PyFrameInfo>,
) -> PyResult<PyBound<'py, PyBytes>> {
    let wtr = Vec::with_capacity(input.len());

    let info_f: FrameInfo = info.unwrap_or_default().into();

    let mut encoder = FrameEncoder::with_frame_info(info_f, wtr);
    encoder.write_all(input).map_err(|e| {
        CompressionError::new_err(format!("Failed to LZ4 compression into buffer: {}.", e))
    })?;

    let output = encoder.finish().map_err(|e| {
        CompressionError::new_err(format!("Failed to finish LZ4 compression: {}.", e))
    })?;

    Ok(PyBytes::new(py, &output))
}
/// Decompresses a buffer of bytes using thex LZ4 frame format.
/// Args:
///     input (`bytes`):
///         A byte containing LZ4-compressed data (in frame format).
///         Typically obtained from a prior call to an `compress` or read from
///         a compressed file `compress_into_file`.
/// Returns:
///     (`bytes`):
///         the decompressed (original) representation of the input bytes.
#[pyfunction]
#[pyo3(signature = (input))]
fn decompress<'py>(py: Python<'py>, input: &[u8]) -> PyResult<PyBound<'py, PyBytes>> {
    let mut decoder = FrameDecoder::new(input);
    let mut buffer = Vec::new();
    decoder.read_to_end(&mut buffer).map_err(|e| {
        DecompressionError::new_err(format!("Decompression failed while reading: {} ", e))
    })?;
    Ok(PyBytes::new(py, &buffer))
}

/// Decompresses a buffer of bytes into a file using thex LZ4 frame format.
///
/// Args:
///    filename (`str` or `os.PathLike`):
///        The filename we are loading from.
///
/// Returns:
///    (`bytes`):
///        The decompressed (original) representation of the input bytes.
/// Example:
///
/// ```python
/// from safelz4 import decompress
///
/// output = decompress("datafile.lz4")
/// ```
#[pyfunction]
#[pyo3(signature = (filename))]
fn decompress_file(py: Python<'_>, filename: PathBuf) -> PyResult<PyBound<'_, PyBytes>> {
    let file = std::fs::File::open(&filename)
        .map_err(|_| PyFileExistsError::new_err(format!("{filename:?} already exist.")))?;
    let rdr = std::io::BufReader::new(file);
    let mut decoder = FrameDecoder::new(rdr);

    let mut buffer = Vec::new();
    decoder.read_to_end(&mut buffer).map_err(|e| {
        DecompressionError::new_err(format!(
            "Decompression failed while reading {:?}: {}",
            filename, e
        ))
    })?;
    Ok(PyBytes::new(py, &buffer))
}

/// IO File mode.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum LZ4FileMode {
    READ_BYTES(String),
    WRITE_BYTES(String),
}

impl TryFrom<&str> for LZ4FileMode {
    type Error = PyErr;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            mode @ "rb" => Ok(LZ4FileMode::READ_BYTES(mode.into())),
            mode @ "rb|lz4" => Ok(LZ4FileMode::READ_BYTES(mode.into())),
            mode @ "wb" => Ok(LZ4FileMode::WRITE_BYTES(mode.into())),
            mode @ "wb|lz4" => Ok(LZ4FileMode::WRITE_BYTES(mode.into())),
            m => Err(PyValueError::new_err(format!(
                "{:?} is not a valid file mode",
                m
            ))),
        }
    }
}

impl From<LZ4FileMode> for String {
    fn from(value: LZ4FileMode) -> Self {
        match value {
            LZ4FileMode::READ_BYTES(mode) => mode,
            LZ4FileMode::WRITE_BYTES(mode) => mode,
        }
    }
}

/// Enum on possible Block Repersentations
enum BlockInfo {
    Uncompressed(u32),
    Compressed(u32),
    Eof,
}

impl BlockInfo {
    pub(crate) fn read(input: &[u8]) -> PyResult<Self> {
        let array = [input[0], input[1], input[2], input[3]];
        let size = u32::from_le_bytes(array);
        if size == 0 {
            Ok(BlockInfo::Eof)
        } else if size & BLOCK_UNCOMPRESSED_SIZE_BIT != 0 {
            Ok(BlockInfo::Uncompressed(size & !BLOCK_UNCOMPRESSED_SIZE_BIT))
        } else {
            Ok(BlockInfo::Compressed(size))
        }
    }
}

/// Read and parse an LZ4 frame file in memory using memory mapping.
///
/// Args:
///     filename (`str` or `os.PathLike`):
///         Path to the LZ4 frame file.
///
/// Raises:
///     (`IOError`): If the file cannot be opened or memory-mapped.
///     (`ReadError`): If reading invalid memeory in the mmap.
///     (`HeaderError`): If reading file header fails.
///     (`DecompressionError`): If decompressing
///
#[pyclass]
#[pyo3(name = "FrameDecoderReader")]
struct PyFrameDecoderReader {
    /// name of the file.
    name: PathBuf,
    /// mode (read bytes un/compressed)
    mode: LZ4FileMode,
    /// file header
    frame_info: PyFrameInfo,
    /// from file header the offset of the blocks
    offset: usize,
    // moving counter of the current block
    current_block: usize,
    /// Current block the reader is at
    content_len: u64,
    /// The compressed bytes buffer, taken from the underlying reader.
    src: Vec<u8>,
    /// The decompressed bytes buffer. Bytes are decompressed from src to dst
    /// before being passed back to the caller.
    dst: Vec<u8>,
    /// Index into dst and length: starting point of bytes previously output
    /// that are still part of the decompressor window.
    ext_dict_offset: usize,
    ext_dict_len: usize,
    /// Index into dst: starting point of bytes not yet read by caller.
    dst_start: usize,
    /// Index into dst: ending point of bytes not yet read by caller.
    dst_end: usize,
    content_hasher: XxHash32,
    /// inner buffer memeory of compressed bytes
    inner: Option<Arc<Mmap>>,
}

impl PyFrameDecoderReader {
    /// Atomic reference to the memory map allowing for fast read only access  
    pub(crate) fn inner(&self) -> PyResult<Arc<Mmap>> {
        match &self.inner {
            Some(arc) => Ok(Arc::clone(arc)), // Explicit Arc::clone
            None => Err(ReadError::new_err("File is closed".to_string())),
        }
    }

    /// fill full buffer from start to end dst (output buffer)
    pub(crate) fn fill_buf(&mut self) -> PyResult<&[u8]> {
        if self.dst_start == self.dst_end {
            self.read_block()?;
        }
        Ok(&self.dst[self.dst_start..self.dst_end])
    }

    /// set the output buffer to dst_start
    pub(crate) fn consume(&mut self, amt: usize) {
        assert!(amt <= self.dst_end - self.dst_start);
        self.dst_start += amt;
    }

    /// read the checksum u32.
    #[inline]
    pub(crate) fn read_checksum(input: &[u8], position: usize) -> PyResult<u32> {
        if input.len() < position + 4 {
            // Check if we have 4 bytes from position
            return Err(ReadError::new_err(
                "Not enough bytes to read checksum at position",
            ));
        }
        let array = [
            input[position],
            input[position + 1],
            input[position + 2],
            input[position + 3],
        ];
        let checksum = u32::from_le_bytes(array);
        Ok(checksum)
    }

    /// Read the block checksum.
    #[inline]
    pub(crate) fn check_block_checksum(data: &[u8], expected_checksum: u32) -> PyResult<()> {
        let mut block_hasher = XxHash32::with_seed(0);
        block_hasher.write(data);
        let calc_checksum = block_hasher.finish() as u32;
        if calc_checksum != expected_checksum {
            return Err(LZ4BlockError::new_err(format!(
                "The block checksum doesn't match. Expected {expected_checksum}"
            )));
        }
        Ok(())
    }

    /// Read singular block, and decomrpess the  
    pub(crate) fn read_block(&mut self) -> PyResult<usize> {
        let frame_info = &self.frame_info;

        // Adjust dst buffer offsets to decompress the next block
        let max_block_size = frame_info.block_size.get_size()?;
        if frame_info.block_mode == PyBlockMode::Linked {
            // In linked mode we consume the output (bumping dst_start) but leave the
            // beginning of dst to be used as a prefix in subsequent blocks.
            // That is at least until we have at least `max_block_size + WINDOW_SIZE`
            // bytes in dst, then we setup an ext_dict with the last WINDOW_SIZE bytes
            // and the output goes to the beginning of dst again.
            debug_assert_eq!(self.dst.capacity(), max_block_size * 2 + WINDOW_SIZE);
            if self.dst_start + max_block_size > self.dst.capacity() {
                // Output might not fit in the buffer.
                // The ext_dict will become the last WINDOW_SIZE bytes
                debug_assert!(self.dst_start >= max_block_size + WINDOW_SIZE);
                self.ext_dict_offset = self.dst_start - WINDOW_SIZE;
                self.ext_dict_len = WINDOW_SIZE;
                // Output goes in the beginning of the buffer again.
                self.dst_start = 0;
                self.dst_end = 0;
            } else if self.dst_start + self.ext_dict_len > WINDOW_SIZE {
                // There's more than WINDOW_SIZE bytes of lookback adding the prefix and ext_dict.
                // Since we have a limited buffer we must shrink ext_dict in favor of the prefix,
                // so that we can fit up to max_block_size bytes between dst_start and ext_dict
                // start.
                let delta = self
                    .ext_dict_len
                    .min(self.dst_start + self.ext_dict_len - WINDOW_SIZE);
                self.ext_dict_offset += delta;
                self.ext_dict_len -= delta;
                debug_assert!(self.dst_start + self.ext_dict_len >= WINDOW_SIZE)
            }
        } else {
            debug_assert_eq!(self.ext_dict_len, 0);
            debug_assert_eq!(self.dst.capacity(), max_block_size);
            self.dst_start = 0;
            self.dst_end = 0;
        }

        let buffer = &self.inner()?;
        // Read and decompress block
        let block_info = {
            let block_buffer = buffer.get(self.offset..self.offset + 4);
            if let Some(output) = block_buffer {
                // increment blockinfo 4 bytes
                self.offset += 4;
                BlockInfo::read(output)?
            } else {
                return Ok(0);
            }
        };

        match block_info {
            BlockInfo::Uncompressed(len) => {
                let len = len as usize;
                if len > max_block_size {
                    return Err(ReadError::new_err(
                        "Read a block larger than specified in the Frame header.",
                    ));
                }
                // TODO: Attempt to avoid initialization of read buffer when
                // https://github.com/rust-lang/rust/issues/42788 stabilizes
                let output =
                    vec_resize_and_get_mut(&mut self.dst, self.dst_start, self.dst_start + len);

                output.copy_from_slice(&buffer[self.offset..self.offset + len]);
                self.offset += len;

                if frame_info.block_checksums {
                    let expected_checksum = Self::read_checksum(buffer, self.offset)?;
                    Self::check_block_checksum(
                        &self.dst[self.dst_start..self.dst_start + len],
                        expected_checksum,
                    )?;
                }

                self.dst_end += len;
                self.content_len += len as u64;
            }
            BlockInfo::Compressed(len) => {
                let len = len as usize;
                if len > max_block_size {
                    return Err(ReadError::new_err(
                        "Read a block larger than specified in the Frame header.",
                    ));
                }
                // TODO: Attempt to avoid initialization of read buffer when
                // https://github.com/rust-lang/rust/issues/42788 stabilizes
                let output = vec_resize_and_get_mut(&mut self.src, 0, len);

                output.copy_from_slice(&buffer[self.offset..self.offset + len]);
                self.offset += len;

                if frame_info.block_checksums {
                    let expected_checksum = Self::read_checksum(buffer, self.offset)?;
                    Self::check_block_checksum(&self.src[..len], expected_checksum)?;
                }

                let with_dict_mode =
                    frame_info.block_mode == PyBlockMode::Linked && self.ext_dict_len != 0;
                let decomp_size = if with_dict_mode {
                    debug_assert!(self.dst_start + max_block_size <= self.ext_dict_offset);
                    let (head, tail) = self.dst.split_at_mut(self.ext_dict_offset);
                    let ext_dict = &tail[..self.ext_dict_len];

                    debug_assert!(head.len() - self.dst_start >= max_block_size);
                    lz4_flex::block::decompress_into_with_dict(
                        &self.src[..len],
                        &mut head[..self.dst_start],
                        ext_dict,
                    )
                } else {
                    // Independent blocks OR linked blocks with only prefix data
                    debug_assert!(self.dst.capacity() - self.dst_start >= max_block_size);
                    self.dst.resize(self.dst_start + max_block_size, 0);
                    lz4_flex::block::decompress_into(&self.src[..len], &mut self.dst)
                }
                .map_err(|e| DecompressionError::new_err(format!("{}", e)))?;

                self.dst_end += decomp_size;
                self.content_len += decomp_size as u64;
            }

            BlockInfo::Eof => {
                if let Some(expected) = frame_info.content_size {
                    if self.content_len != expected {
                        return Err(ReadError::new_err(format!(
                            "Content length differs. Expected {expected}, and got {}",
                            self.content_len
                        )));
                    }
                }
                if frame_info.content_checksum {
                    let expected_checksum = Self::read_checksum(buffer, self.offset)?;
                    let calc_checksum = self.content_hasher.finish() as u32;
                    if calc_checksum != expected_checksum {
                        return Err(ReadError::new_err(format!("The block checksum doesn't match. Expected {expected_checksum}, actually got {calc_checksum}")));
                    }
                }
                return Ok(0);
            }
        }

        // Content checksum, if applicable
        if frame_info.content_checksum {
            self.content_hasher
                .write(&self.dst[self.dst_start..self.dst_end]);
        }
        // increment current block read
        self.current_block += 1;
        Ok(self.dst_end - self.dst_start)
    }

    /// read bytes till the end.
    pub(crate) fn read_to_end(&mut self, buf: &mut Vec<u8>) -> PyResult<usize> {
        let mut written = 0;
        loop {
            match self.fill_buf() {
                Ok([]) => return Ok(written),
                Ok(b) => {
                    buf.extend_from_slice(b);
                    let len = b.len();
                    self.consume(len);
                    written += len;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[pymethods]
impl PyFrameDecoderReader {
    #[new]
    #[pyo3(signature = (filename, mode = None))]
    pub fn new(filename: PathBuf, mode: Option<&str>) -> PyResult<Self> {
        let mode: LZ4FileMode = match mode {
            Some(value) => value.try_into()?,
            None => LZ4FileMode::READ_BYTES(String::from("rb")),
        };
        let file = File::open(&filename).map_err(|e| {
            PyIOError::new_err(format!("Failed to open file {:?}: {}", filename, e))
        })?;

        // inner read only memory map of the file
        let inner = Arc::new(unsafe {
            MmapOptions::new()
                .map_copy_read_only(&file)
                .map_err(|e| PyIOError::new_err(format!("Failed to mmap file: {}", e)))?
        });

        if inner.len() < MIN_FRAME_INFO_SIZE {
            return Err(HeaderError::new_err("header is too small to be lz4."));
        }

        let offset = PyFrameInfo::read_header_size(&inner)?;

        let frame_info = PyFrameInfo::read_header_info(&inner[..offset])?;
        if frame_info.dict_id.is_some() {
            // Unsupported right now so it must be None
            return Err(LZ4Exception::new_err(
                "dict_id is currently not supported at this time.",
            ));
        }

        let max_block_size = frame_info.block_size.get_size()?;
        let dst_size = if frame_info.block_mode == PyBlockMode::Linked {
            // In linked mode we consume the output (bumping dst_start) but leave the
            // beginning of dst to be used as a prefix in subsequent blocks.
            // That is at least until we have at least `max_block_size + WINDOW_SIZE`
            // bytes in dst, then we setup an ext_dict with the last WINDOW_SIZE bytes
            // and the output goes to the beginning of dst again.
            // Since we always want to be able to write a full block (up to max_block_size)
            // we need a buffer with at least `max_block_size * 2 + WINDOW_SIZE` bytes.
            max_block_size * 2 + WINDOW_SIZE
        } else {
            max_block_size
        };

        let src = Vec::with_capacity(max_block_size);
        let dst = Vec::with_capacity(dst_size);

        Ok(Self {
            name: filename,
            mode,
            frame_info,
            offset,
            src,
            dst,
            current_block: 0,
            ext_dict_offset: 0,
            ext_dict_len: 0,
            dst_start: 0,
            dst_end: 0,
            content_hasher: XxHash32::with_seed(0),
            content_len: 0,
            inner: Some(inner),
        })
    }

    #[getter]
    /// return the name of the file
    pub fn name(&self) -> PyResult<PathBuf> {
        Ok(self.name.clone())
    }

    /// Return mode of the reader.
    #[getter]
    pub fn mode(&self) -> PyResult<String> {
        Ok(self.mode.clone().into())
    }

    /// check if the inner is closed.
    #[getter]
    fn closed(&self) -> PyResult<bool> {
        match self.inner {
            None => Ok(true),
            _ => Ok(false),
        }
    }

    /// Returns the offset after the LZ4 frame header.
    /// Returns:
    ///     (`int`): Offset in bytes to the start of the first data block.
    #[getter]
    pub fn offset(&self) -> PyResult<usize> {
        Ok(self.offset)
    }

    /// Return the amounf of blocks that has been read.
    /// Returns:
    ///     (`int`): current block number.
    #[getter]
    pub fn current_block(&self) -> PyResult<usize> {
        Ok(self.current_block)
    }

    /// Returns the content size specified in the LZ4 frame header.
    /// Returns:
    ///     (`Optional[int]`): Content size if present, or None.
    #[getter]
    pub fn content_size(&self) -> PyResult<Option<u64>> {
        self.frame_info.get_content_size()
    }

    /// Returns the block size used in the LZ4 frame.
    /// Returns:
    ///     (`BlockSize`): Enum representing the block size.
    #[getter]
    pub fn block_size(&self) -> PyResult<PyBlockSize> {
        self.frame_info.get_block_size()
    }

    /// Checks if block checksums are enabled for this frame.
    /// Returns:
    ///     (`bool`): True if block checksums are enabled, False otherwise.
    #[getter]
    pub fn block_checksum(&self) -> PyResult<bool> {
        self.frame_info.get_block_checksums()
    }

    /// Returns a copy of the parsed frame header.
    /// Returns:
    ///     (`FrameInfo`): Frame header metadata object.
    #[getter]
    pub fn frame_info(&self) -> PyResult<PyFrameInfo> {
        Ok(self.frame_info)
    }

    /// Reads and returns a decompressed block of the specified size.
    /// This method attempts to read a block of compressed data
    /// and decompress it into the desired size. It is typically used
    /// when working with framed compression formats such as LZ4.
    /// Args:
    ///     size (`int`): The number of bytes to return after decompression.
    /// Returns:
    ///     (`bytes`): A decompressed byte string of the requested size.
    /// Raises:
    ///     (`ReadError`):
    ///         Raised if the input stream cannot be read or is incomplete.
    ///     (`DecompressionError`):
    ///         Raised if the source buffer cannot be decompressed
    ///         into the destination buffer, typically due to corrupt or
    ///         malformed input.
    ///     (`LZ4Exception`):
    ///         Raised if a block checksum does not match the expected value,
    ///         indicating potential data corruption.
    #[pyo3(signature = (size = -1))]
    pub fn read<'py>(
        &mut self,
        py: Python<'py>,
        size: Option<isize>,
    ) -> PyResult<Option<PyBound<'py, PyBytes>>> {
        let closed = self.closed()?;
        if closed {
            return Err(PyValueError::new_err("I/O operation on closed file"));
        }

        let size = size.unwrap_or(-1);
        if size == 0 {
            Ok(Some(PyBytes::new(py, &[])))
        } else if size == -1 {
            let capacity = self.frame_info.block_size.get_size()?;
            let mut buf = Vec::with_capacity(capacity);
            let _ = self.read_to_end(&mut buf)?;
            Ok(Some(PyBytes::new(py, &buf)))
        } else if size > 0 {
            let mut buf = vec![0u8; size as usize];
            loop {
                // Fill read buffer if there's uncompressed data left
                if self.dst_start < self.dst_end {
                    let read_len = std::cmp::min(self.dst_end - self.dst_start, buf.len());
                    let dst_read_end = self.dst_start + read_len;
                    buf[..read_len].copy_from_slice(&self.dst[self.dst_start..dst_read_end]);

                    self.dst_start = dst_read_end;

                    return Ok(Some(PyBytes::new(py, &buf[..read_len])));
                }
                if self.read_block()? == 0 {
                    return Ok(None);
                }
            }
        } else {
            Err(PyValueError::new_err(
                "read length must be non-negative or -1",
            ))
        }
    }

    /// drop the Arc<Mmap>
    fn close(&mut self) {
        self.inner = None
    }

    /// Context manager entry — returns self.
    /// Returns:
    ///     (`FrameDecoderReader`): The reader instance itself.
    pub fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Context manager exit
    pub fn __exit__(&mut self, _exc_type: PyObject, _exc_value: PyObject, _traceback: PyObject) {
        // INFO: by setting the inner storage to `None` we drop all the memeory
        //       the mmap has allocated.
        self.close();
    }

    fn __repr__(&self) -> String {
        format!("<_frame.FrameDecoderReader name={:?}>", self.name,)
    }

    fn __str__(&self) -> String {
        format!("<_frame.FrameDecoderReader name={:?}>", self.name,)
    }
}

#[inline]
fn vec_resize_and_get_mut(v: &mut Vec<u8>, start: usize, end: usize) -> &mut [u8] {
    if end > v.len() {
        v.resize(end, 0)
    }
    &mut v[start..end]
}

#[pyclass]
#[pyo3(name = "FrameEncoderWriter")]
struct PyFrameEncoderWriter {
    /// name of the file.
    name: PathBuf,
    /// cached mode type.
    mode: LZ4FileMode,
    /// writer offset counter.
    offset: usize,
    /// underlying Frame Encoder over file buffer writer.
    inner: Option<FrameEncoder<BufWriter<File>>>,
}

impl PyFrameEncoderWriter {
    pub(crate) fn inner(&mut self) -> PyResult<&mut FrameEncoder<BufWriter<File>>> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| LZ4Exception::new_err("File is closed".to_string()))?;
        Ok(inner)
    }
}

#[pymethods]
impl PyFrameEncoderWriter {
    #[new]
    #[pyo3(signature = (filename, mode, block_size, block_mode, block_checksums = None, dict_id = None, content_checksum = None, content_size = None, legacy_frame = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        filename: PathBuf,
        mode: Option<&str>,
        block_size: PyBlockSize,
        block_mode: PyBlockMode,
        block_checksums: Option<bool>,
        dict_id: Option<u32>,
        content_checksum: Option<bool>,
        content_size: Option<u64>,
        legacy_frame: Option<bool>,
    ) -> PyResult<Self> {
        let file = File::create(&filename).map_err(|e| {
            PyIOError::new_err(format!("Failed to create file {:?}: {}", filename, e))
        })?;

        let wtr = BufWriter::new(file);

        let frame_info: FrameInfo = PyFrameInfo::new(
            block_size,
            block_mode,
            block_checksums,
            dict_id,
            content_checksum,
            content_size,
            legacy_frame,
        )
        .into();
        let inner = Some(FrameEncoder::with_frame_info(frame_info, wtr));

        let mode = match mode {
            Some(value) => value.try_into()?,
            None => LZ4FileMode::WRITE_BYTES(String::from("wb")),
        };

        Ok(Self {
            name: filename,
            mode,
            offset: 0,
            inner,
        })
    }

    #[getter]
    /// return the name of the file
    pub fn name(&self) -> PyResult<PathBuf> {
        Ok(self.name.clone())
    }

    /// Return mode of the writer.
    #[getter]
    pub fn mode(&self) -> PyResult<String> {
        Ok(self.mode.clone().into())
    }

    /// current total bytes written into writer.
    #[getter]
    fn offset(&self) -> PyResult<usize> {
        Ok(self.offset)
    }

    /// current frame info
    #[getter]
    fn frame_info(&mut self) -> PyResult<PyFrameInfo> {
        Ok(self.inner()?.frame_info().clone().into())
    }

    /// write bytes into writer
    pub fn write(&mut self, input: &[u8]) -> PyResult<usize> {
        let offset = self
            .inner()?
            .write(input)
            .map_err(|e| CompressionError::new_err(format!("{}", e)))?;
        self.offset += offset;
        Ok(offset)
    }

    /// Flushes this output stream, ensuring that all intermediately buffered contents reach their destination.
    pub fn flush(&mut self) -> PyResult<()> {
        self.inner()?
            .flush()
            .map_err(|e| PyIOError::new_err(format!("{}", e)))
    }

    #[getter]
    fn closed(&self) -> PyResult<bool> {
        match self.inner {
            None => Ok(true),
            _ => Ok(false),
        }
    }

    pub fn close(&mut self) -> PyResult<()> {
        self.flush()?;
        self.inner = None;
        Ok(())
    }

    pub fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    pub fn __exit__(
        &mut self,
        _exc_type: PyObject,
        _exc_value: PyObject,
        _traceback: PyObject,
    ) -> PyResult<()> {
        self.close()
    }

    fn __repr__(&self) -> String {
        format!("<_frame.FrameEncoderWriter name={:?}>", self.name,)
    }

    fn __str__(&self) -> String {
        format!("<_frame.FrameEncoderWriter name={:?}>", self.name,)
    }
}
/// Check if a file is a valid LZ4 Frame file by reading its header
///
/// Args:
///     filename (`str`): Path to check
///
/// Returns:
///     (`bool)`: True if the file appears to be a valid LZ4 file
#[pyfunction]
pub fn is_framefile(filename: PathBuf) -> PyResult<bool> {
    match File::open(&filename) {
        Ok(file) => match unsafe { MmapOptions::new().map_copy_read_only(&file) } {
            Ok(mmap) => match PyFrameInfo::read_header_info(&mmap) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            },
            Err(_) => Ok(false),
        },
        Err(_) => Ok(false),
    }
}

/// register frame module handles which handles Frame de/compression of frames.
///
/// ```ignore
/// from ._safelz4_rs import _frame
///
/// plaintext = b"eeeeeeee Hello world this is an example of plaintext being compressed eeeeeeeeeeeeeee"
/// output = _frame.compress(plaintext)
/// output = _frame.decompress(output)
/// ```
pub(crate) fn register_frame_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let frame_m = PyModule::new(m.py(), "_frame")?;

    // function
    frame_m.add_function(wrap_pyfunction!(compress, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(compress_into_file, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(compress_into_file_with_info, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(compress_with_info, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(decompress_file, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(decompress, &frame_m)?)?;
    frame_m.add_function(wrap_pyfunction!(is_framefile, &frame_m)?)?;

    // class objects
    frame_m.add_class::<PyFrameInfo>()?;
    frame_m.add_class::<PyBlockMode>()?;
    frame_m.add_class::<PyBlockSize>()?;

    // IO Read/Write
    frame_m.add_class::<PyFrameDecoderReader>()?;
    frame_m.add_class::<PyFrameEncoderWriter>()?;

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
