import os
import io
from typing import Optional, Union, Literal, Final, List, IO, overload
from types import TracebackType

try:
    from typing import Self
except ImportError:
    # NOTE For Python < 3.12
    from typing_extensions import Self

from enum import IntEnum, Enum

FLG_RESERVED_MASK: Final[int]
FLG_VERSION_MASK: Final[int]
FLG_SUPPORTED_VERSION_BITS: Final[int]

FLG_INDEPENDENT_BLOCKS: Final[int]
FLG_BLOCK_CHECKSUMS: Final[int]
FLG_CONTENT_SIZE: Final[int]
FLG_CONTENT_CHECKSUM: Final[int]
FLG_DICTIONARY_ID: Final[int]

BD_RESERVED_MASK: Final[int]
BD_BLOCK_SIZE_MASK: Final[int]
BD_BLOCK_SIZE_MASK_RSHIFT: Final[int]

LZ4F_MAGIC_NUMBER: Final[int]
LZ4F_LEGACY_MAGIC_NUMBER: Final[int]

MAGIC_NUMBER_SIZE: Final[int]
MIN_FRAME_INFO_SIZE: Final[int]
MAX_FRAME_INFO_SIZE: Final[int]
BLOCK_INFO_SIZE: Final[int]

class BlockMode(Enum):
    """
    Block mode for frame compression.

    Attributes:
        Independent: Independent block mode.
        Linked: Linked block mode.
    """

    Independent = "Independent"
    Linked = "Linked"

class BlockSize(IntEnum):
    """
    Size of individual compressed or uncompressed data
    blocks within the frame.

    Attributes:
        Auto: Will detect optimal frame size based on the size of the first
        write call.
        Max64KB: The default block size (64KB).
        Max256KB: 256KB block size.
        Max1MB: 1MB block size.
        Max4MB: 4MB block size.
        Max8MB: 8MB block size.
    """

    Auto = 0
    Max64KB = 4
    Max256KB = 5
    Max1MB = 6
    Max4MB = 7
    Max8MB = 8

    @staticmethod
    def from_buf_length(buf_len: int):
        """Try to find optimal size based on passed buffer length."""
        ...
    def get_size(self) -> int:
        """Return the size in bytes"""
        ...

class FrameInfo:
    """
    Information about a compression frame.
    """

    content_size: Optional[int]
    block_size: BlockSize
    block_mode: BlockMode
    block_checksums: bool
    dict_id: Optional[int]
    content_checksum: bool
    legacy_frame: bool

    def __new__(
        self,
        block_size: BlockSize,
        block_mode: BlockMode,
        block_checksums: Optional[bool] = None,
        dict_id: Optional[int] = None,
        content_checksum: Optional[bool] = None,
        content_size: Optional[int] = None,
        legacy_frame: Optional[bool] = None,
    ) -> Self: ...
    @staticmethod
    def default() -> Self:
        """
        build a default `FrameInfo` class.

        Returns:
            (`FrameInfo`): default object.
        """
        ...
    @staticmethod
    def read_header_info(input: bytes) -> Self:
        """Read bytes info to construct frame header."""
        ...
    def read_header_size(input: bytes) -> Self:
        """Read the size of the frame header info"""
        ...
    @property
    def block_checksums(self) -> bool: ...
    @block_checksums.setter
    def block_checksums(self, value: bool) -> None: ...
    @property
    def block_size(self) -> BlockSize: ...
    @block_size.setter
    def block_size(self, value: BlockSize) -> None: ...
    @property
    def block_mode(self) -> BlockMode: ...
    @property
    def content_size(self) -> Optional[int]: ...
    @content_size.setter
    def content_size(self, value: int) -> None: ...
    @property
    def content_sum(self) -> bool: ...
    @property
    def content_checksum(self) -> bool: ...
    @content_checksum.setter
    def content_checksum(self, value: bool) -> None: ...
    @property
    def legacy_frame(self) -> bool: ...
    @legacy_frame.setter
    def legacy_frame(self, value: bool) -> None: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...

def decompress(input: bytes) -> bytes:
    """
    Decompresses a buffer of bytes using thex LZ4 frame format.

    Args:
        input (`bytes`):
            A byte containing LZ4-compressed data (in frame format).
            Typically obtained from a prior call to an `compress` or read from
            a compressed file `compress_into_file`.

    Returns:
        (`bytes`):
            the decompressed (original) representation of the input bytes.

    Example:

    ```python
    from safelz4 import decompress

    output = None
    with open("datafile.lz4", "r")  as file:
        buffer = file.read(-1).encode("utf-8")
        output = decompress(buffer)
    ```
    """
    ...

def decompress_file(filename: Union[os.PathLike, str]) -> bytes:
    """
    Decompresses a buffer of bytes into a file using thex LZ4 frame format.

    Args:
        filename (`str` or `os.PathLike`):
            The filename we are loading from.

    Returns:
        (`bytes`):
            the decompressed (original) representation of the input bytes.

    Example:

    ```python
    from safelz4 import decompress

    output = decompress("datafile.lz4")
    ```

    """
    ...

def compress(input: bytes) -> bytes:
    """
    Compresses a buffer of LZ4-compressed bytes using the LZ4 frame format.

    Args:
        input (`bytes`):
            An arbitrary byte buffer to be compressed.
    Returns:
        (`bytes`):
             the LZ4 frame-compressed representation of the input bytes.

    Example:
    ```python
    from safelz4.frame import compress

    buffer = None
    with open("datafile.txt", "rb") as file:
        output = file.read(-1)
        buffer = compress(output)

    ```
    """
    ...

def compress_into_file(filename: Union[os.PathLike, str], input: bytes) -> None:
    """
    Compresses a buffer of bytes into a file using using the LZ4 frame format.

    Args:
        filename (`str` or `os.PathLike`):
            The filename we are saving into.
        input (`bytes`):
            un-compressed representation of the input bytes.

    Returns:
        (`None`)

    Example:
    ```python
    from safelz4.frame import compress

    with open("datafile.txt", "rb") as file:
        buffer = file.read(-1)
        compress_into_file("datafile.lz4", buf_f)

    ```
    """
    ...

def compress_into_file_with_info(
    filename: Union[os.PathLike, str],
    input: bytes,
    info: Optional[FrameInfo] = None,
) -> None:
    """
    Compresses a buffer of bytes into a file using using the LZ4 frame format,
    with more control on Block Linkage.

    Args:
        filename (`str`, or `os.PathLike`):
            The filename we are saving into.
        input (`bytes`):
            fixed set of bytes to be compressed.
        info (`FrameInfo`, *optional*, defaults to `None`):
            The metadata for de/compressing with lz4 frame format.

    Returns:
        (`None`)
    """
    ...

def compress_with_info(
    input: bytes,
    info: Optional[FrameInfo] = None,
) -> None:
    """
    Compresses a buffer of bytes into byte buffer using using the LZ4 frame
    format, with more control on Frame.

    Args:
        input (`bytes`):
            fixed set of bytes to be compressed.
        info (`FrameInfo`, *optional*, defaults to `None`):
            The metadata for de/compressing with lz4 frame format.

    Returns:
        (`bytes`):
            the LZ4 frame-compressed representation of the input bytes.
    """
    ...

@overload
def is_framefile(name: Union[os.PathLike, str]) -> bool:
    """
    Check if a file is a valid LZ4 Frame file by reading its header

    Args:
        name (`str` or `os.PathLike`):
            The filename we are saving into.

    Returns:
        (`bool`): true if the file appears to be a valid LZ4 file
    """
    ...

@overload
def is_framefile(name: bytes) -> bool:
    """
    Check if a file is a valid LZ4 Frame file by reading its header

    Args:
        name (`bytes`):
            Abritary fixed set of bytes.

    Returns:
        (`bool)`: true if the file appears to be a valid LZ4 file
    """
    ...

@overload
def is_framefile(name: io.BufferedReader) -> bool:
    """
    Check if a file is a valid LZ4 Frame file by reading its header

    Args:
        name (`io.BufferedReader`):
            Io reader to which we can read fix sized bytes.

    Returns:
        (`bool)`: true if the file appears to be a valid LZ4 file
    """
    ...

def decompress_prepend_size_with_dict(input: bytes, ext_dict: bytes) -> bytes:
    """
    Decompress input bytes using a user-provided dictionary of bytes,
    size is already pre-appended.
    Args:
        input (`bytes`):
            fixed set of bytes to be decompressed.
        ext_dict (`bytes`):
            Dictionary used for decompression.

    Returns:
        (`bytes`): decompressed data.
    """
    ...

class FrameDecoderReader:
    """
    Read and parse an LZ4 frame file in memory using memory mapping.

    Args:
        filename (`str` or `os.PathLike`):
            Path to the LZ4 frame file.

    Raises:
        (`IOError`):
            Rasied if the file cannot be opened or memory-mapped.
        (`ReadError`):
            Raised if reading invalid memeory in the mmap.
        (`HeaderError`):
            Rasied if reading file header fails.
    """

    def __new__(self, filename: Union[os.PathLike, str]) -> Self: ...
    @getattr
    def closed(self) -> bool: ...
    @getattr
    def name(self) -> str: ...
    @getattr
    def mode(self) -> Literal["rb", "rb|lz4"]: ...
    @getattr
    def offset(self) -> int:
        """
        Returns the offset after the LZ4 frame header.

        Returns:
            (`int`): Offset in bytes to the start of the first data block.
        """
        ...
    @getattr
    def current_block(self) -> int:
        """
        Return the amounf of blocks that has been read.

        Returns:
            (`int`): current block number.
        """
        ...
    @getattr
    def content_size(self) -> Optional[int]:
        """
        Returns the content size specified in the LZ4 frame header.

        Returns:
            (`Optional[int]`): Content size if present, or None.
        """
        ...
    @getattr
    def block_size(self) -> BlockSize:
        """
        Returns the block size used in the LZ4 frame.

        Returns:
            (`BlockSize`): Enum representing the block size.
        """
        ...
    @getattr
    def block_checksum(self) -> bool:
        """
        Checks if block checksums are enabled for this frame.

        Returns:
            (`bool`): True if block checksums are enabled, False otherwise.
        """
        ...
    @getattr
    def frame_info(self) -> FrameInfo:
        """
        Returns a copy of the parsed frame header.

        Returns:
            (`FrameInfo`): Frame header metadata object.
        """
        ...
    def read(self, size: int) -> bytes:
        """
        Reads and returns a decompressed block of the specified size.
        This method attempts to read a block of compressed data
        and decompress it into the desired size. It is typically used
        when working with framed compression formats such as LZ4.

        Args:
            size (`int`): The number of bytes to return after decompression.

        Returns:
            (`bytes`): A decompressed byte string of the requested size.

        Raises:
            (`ValueError`):
                Rasied if the file is closed
            (`ReadError`):
                Raised if the input stream cannot be read or is incomplete.
            (`DecompressionError`):
                Raised if the source buffer cannot be decompressed
                into the destination buffer, typically due to corrupt or
                malformed input.
            (`LZ4Exception`):
                Raised if a block checksum does not match the expected value,
                indicating potential data corruption.
        """
        ...
    def close(self) -> None: ...
    def __enter__(self) -> Self:
        """
        Context manager entry.

        Returns:
            (`FrameDecoderReader`): The reader instance itself.
        """
        ...
    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """
        Context manager exit
        """
        ...

class FrameEncoderWriter:
    """
    Write LZ4 frame-compressed data to a file.

    Args:
        filename (`str`):
            Output file path.
        info (`FrameInfo`, *optional*, defaults to `None`):
            Frame parameters; uses defaults if None.

    Raises:
        (`LZ4Exception`):
            Rasied when the file is closed.
        (`CompressionError`):
            Raised when a compression method is not supported or when
            the data cannot be encoded properly.
    """

    def __new__(
        self,
        filename: Union[os.PathLike, str],
        block_size: BlockSize = ...,
        block_mode: BlockMode = ...,
        block_checksums: Optional[bool] = ...,
        dict_id: Optional[int] = ...,
        content_checksum: Optional[bool] = ...,
        content_size: Optional[int] = ...,
        legacy_frame: Optional[bool] = ...,
    ) -> Self: ...
    @getattr
    def closed(self) -> bool: ...
    @getattr
    def name(self) -> str: ...
    @getattr
    def offset(self) -> int:
        """
        Returns the current write offset (total bytes written).

        Returns:
            (`int`): The number of bytes written so far.
        """
        ...
    def write(self, input: bytes) -> int:
        """
        Writes bytes into the LZ4 frame.

        Args:
            input (`bytes`): Input data to compress and write.

        Returns:
            (`int`): Number of bytes written.

        Raises:
            (`CompressionError`): If compression or writing fails.
        """
        ...
    def mode(self) -> Literal["wb", "wb|lz4"]:
        """
        Return current mode

        Returns:
            (`Literal["wb", "rb"]`): mode of reading or writing into file.
        """
        ...
    def flush(self) -> None:
        """
        Flushes the internal buffer to disk.

        Raises:
            (`IOError`): If flushing fails.
        """
        ...
    def close(self) -> None:
        """
        Closes the writer and flushes any remaining data.

        Raises:
            (`IOError`): If flushing fails during close.
        """
        ...
    def __enter__(self) -> Self:
        """
        Context manager entry — returns self.

        Returns:
            (`FrameEncoderWriter`): The writer instance itself.
        """
        ...
    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """
        Context manager exit — flushes and closes the writer.
        """
        ...

class WrappedDecoderReader(IO[bytes]):
    """
    Wrapper that combines IO[bytes] interface with FrameDecoderReader
    functionality. This makes the LZ4 decoder compatible with Python's
    standard I/O system.
    """

    _inner: FrameDecoderReader

    def __init__(
        self,
        filename: Union[os.PathLike, str],
        mode: Optional[Literal["rb", "rb|lz4"]] = None,
    ) -> None: ...
    @property
    def mode(self) -> str: ...
    @property
    def name(self) -> str: ...
    @property
    def closed(self) -> bool: ...
    @property
    def block_size(self) -> BlockSize: ...
    @property
    def content_sized(self) -> Optional[int]: ...
    @property
    def block_checksum(self) -> bool: ...
    @property
    def frame_info(self) -> FrameInfo: ...
    @property
    def current_block(self) -> int: ...
    def readable(self) -> bool:
        """Returns True since this is a readable stream."""
        ...
    def writable(self) -> bool:
        """Returns False since this is read-only."""
        ...
    def seekable(self) -> bool:
        """Returns True if seeking is supported."""
        ...
    def tell(self) -> int:
        """Returns current position in block stream."""
        ...
    def read(self, n: int = -1) -> bytes:
        """
        Read and return up to size bytes.

        Args:
            size (`int`, **optional**, default to -1):
                Number of bytes to read. If -1 or None,
                read all remaining data.

        Returns:
            (`bytes`): block read from the stream return sized bytes of said
                       block.

        Raises:
            (`ValueError`):
                Rasied if the file is closed
            (`ReadError`):
                Raised if the input stream cannot be read or is incomplete.
            (`DecompressionError`):
                Raised if the source buffer cannot be decompressed
                into the destination buffer, typically due to corrupt or
                malformed input.
            (`LZ4Exception`):
                Raised if a block checksum does not match the expected value,
                indicating potential data corruption.
        """
        ...
    def readline(self, limit: int = -1) -> bytes:
        """
        Read and return one line from the stream.

        Args:
            limit (`int`, **optional**, default: -1):
                Maximum number of bytes to read.
                If -1, read until newline or EOF.

        Returns:
            (`bytes`): A single line including the trailing newline character,
                or empty bytes if EOF is reached.

        Raises:
            (`ValueError`):
                Rasied if the file is closed
            (`ReadError`):
                Raised when there is an issue reading the block.
            (`DecompressionError`):
                Raised decompression method is not supported or when
                the data cannot be decoded properly.
        """
        ...
    def readlines(self, hint: int = -1) -> List[bytes]:
        """
        Read and return a list of lines from the stream.

        Args:
            hint (`int`, **optional**, default: -1):
                Approximate number of bytes to read.
                If -1, read all lines.

        Returns:
            (`List[bytes]`): List of lines, each including trailing newline.

        Raises:
            (`ValueError`):
                Raised if the file is closed
        """
        ...
    def __enter__(self) -> Self:
        """Context manager entry"""
        ...
    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """Context manager exit"""
        ...
    def __str__(self): ...
    def __repr__(self): ...

class WrappedEncoderWriter(IO[bytes]):
    """
    Wrapper that combines IO[bytes] interface with
    FrameEncoderWriter functionality. This makes the LZ4
    encoder compatible with Python's standard I/O system.
    """

    _inner: FrameEncoderWriter

    def __init__(
        self,
        filename: Union[os.PathLike, str],
        block_size: BlockSize = ...,
        block_mode: BlockMode = ...,
        block_checksums: Optional[bool] = ...,
        dict_id: Optional[int] = ...,
        content_checksum: Optional[bool] = ...,
        content_size: Optional[int] = ...,
        legacy_frame: Optional[bool] = ...,
    ) -> None: ...
    @property
    def mode(self) -> str: ...
    @property
    def name(self) -> str: ...
    @property
    def closed(self) -> bool: ...
    @property
    def offset(self) -> int: ...
    @property
    def frame_info(self) -> FrameInfo: ...
    def readable(self) -> bool:
        """Returns False since this is write-only."""
        ...
    def writable(self) -> bool:
        """Returns True since this is a writable stream."""
        ...
    def seekable(self) -> bool:
        """
        Returns False since writing streams typically
        don't support seeking.
        """
        ...
    def tell(self) -> int:
        """Returns current position in the stream."""
        ...
    def write(self, data: bytes) -> int:
        """
        Write data to the stream.

        Args:
            (`data`): Data to write.

        Returns:
            (`int`): Number of bytes written.

        Raises:
            (`ValueError`): If the file is closed.
            (`TypeError`): If data is not a bytes-like object.
        """
        ...
    def writelines(self, lines: List[bytes]) -> None:
        """
        Write a list of bytes-like objects to the stream.

        Args:
            lines (`List[bytes]`): Iterable of bytes-like objects.

        Raises:
            (`ValueError`): If the file is closed.
        """
        ...
    def flush(self) -> None:
        """
        Flush the internal buffer to disk.

        Raises:
            (`ValueError`): If the file is closed.
        """
        ...
    def close(self) -> None:
        """
        Close the stream and flush any remaining data.

        Raises:
            (`IOError`): If flushing fails during close.
        """
        ...
    def __enter__(self) -> Self:
        """Context manager entry."""
        ...
    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """Context manager exit."""
        ...
    def __str__(self): ...
    def __repr__(self): ...

@overload
def open(
    filename: Union[str, os.PathLike],
    mode: Optional[Literal["wb", "wb|lz4"]] = None,
    block_size: BlockSize = BlockSize.Auto,
    block_mode: BlockMode = BlockMode.Independent,
    block_checksums: Optional[bool] = None,
    dict_id: Optional[int] = None,
    content_checksum: Optional[bool] = None,
    content_size: Optional[int] = None,
    legacy_frame: Optional[bool] = None,
) -> WrappedEncoderWriter: ...
@overload
def open(
    filename: Union[str, os.PathLike],
    mode: Optional[Literal["rb", "rb|lz4"]] = None,
) -> WrappedDecoderReader: ...
