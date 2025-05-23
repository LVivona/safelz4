import os
import io
from typing import Optional, Union, Any, Literal, overload
from typing_extensions import Self

from enum import IntEnum, Enum

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
    Block size for frame compression.

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

class FrameInfo:
    """
    Information about a compression frame.

    Attributes:
        content_size: If set, includes the total uncompressed size of data in
                      the frame.
        block_size: The maximum uncompressed size of each data block.
        block_mode: The block mode.
        block_checksums: If set, includes a checksum for each data block in the
        frame.
        content_checksum: If set, includes a content checksum to verify that the
          full frame contents have been decoded correctly.
        legacy_frame: If set, use the legacy frame format.
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
        """Read header info to construct header."""
        ...
    def read_header_size(input: bytes) -> Self:
        """Read the size of the header info"""
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
            a compressed file `compress_file`.

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

def compress_file(filename: Union[os.PathLike, str], input: bytes) -> None:
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
        compress_file("datafile.lz4", buf_f)

    ```
    """
    ...

def compress_file_with_info(
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
        info (`FrameInfo, *optional*, defaults to `None``):
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
        info (`FrameInfo, *optional*, defaults to `None``):
            The metadata for de/compressing with lz4 frame format.

    Returns:
        (`bytes`):
            the LZ4 frame-compressed representation of the input bytes.
    """
    ...

@overload
def is_framefile(name: Union[os.PathLike, str]):
    os.PathLike, str
    """Check if a file is a valid LZ4 Frame file by reading its header

    Args:
        filename (`str` or `os.PathLike`): 
            Path to the LZ4 frame file.

    Returns:
        (`bool)`: true if the file appears to be a valid LZ4 file
    """
    ...


@overload
def is_framefile(name: Union[os.PathLike, str, bytes, io.BufferedReader]):...

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

class LZCompressionReader:
    """
    Read and parse an LZ4 frame file in memory using memory mapping.

    Args:
        filename (`str`): Path to the LZ4 frame file.

    Raises:
        (`IOError`): If the file cannot be opened or memory-mapped.
        (`ReadError`): If reading invalid memeory in the mmap.
        (`HeaderError`): If reading file header fails. 
        (`DecompressionError`): If decompressing 

    """

    def __new__(self, filename: str) -> Self: ...
    def offset(self) -> int:
        """
        Returns the offset after the LZ4 frame header.

        Returns:
            int: Offset in bytes to the start of the first data block.
        """
        ...
    def content_size(self) -> Optional[int]:
        """
        Returns the content size specified in the LZ4 frame header.

        Returns:
            Optional[int]: Content size if present, or None.
        """
        ...
    def block_size(self) -> BlockSize:
        """
        Returns the block size used in the LZ4 frame.

        Returns:
            PyBlockSize: Enum representing the block size.
        """
        ...
    def block_checksum(self) -> bool:
        """
        Checks if block checksums are enabled for this frame.

        Returns:
            bool: True if block checksums are enabled, False otherwise.
        """
        ...
    def frame_info(self) -> FrameInfo:
        """
        Returns a copy of the parsed frame header.

        Returns:
            PyFrameInfo: Frame header metadata object.
        """
        ...
    def get_block(self, idx: int) -> bytes:
        """
        Reads and returns a decompressed block at the given index.

        Args:
            idx (int): Block index to read.

        Returns:
            bytes: The decompressed block data.

        Raises:
            IndexError: If the block index is out of range.
            LZ4Exception: If block decompression fails.
        """
        ...
    def __iter__(self) -> Self: ...
    def __next__(self) -> bytes: ...
    def __enter__(self) -> Self:
        """
        Context manager entry — returns self.

        Returns:
            FrameDecoderReader: The reader instance itself.
        """
        ...
    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[Any],
    ) -> None:
        """
        Context manager exit — releases memory mapping.
        """
        ...

class LZCompressionWriter:
    """
    Write LZ4 frame-compressed data to a file.

    Args:
        filename (str): Output file path.
        info (Optional[PyFrameInfo]): Frame parameters; uses defaults if None.

    Raises:
        IOError: If the file cannot be opened for writing.
    """

    def __new__(self, filename: str, info: Optional[FrameInfo] = None) -> Self: ...
    def offset(self) -> int:
        """
        Returns the current write offset (total bytes written).

        Returns:
            int: The number of bytes written so far.
        """
        ...
    def write(self, input: bytes) -> int:
        """
        Writes bytes into the LZ4 frame.

        Args:
            input (bytes): Input data to compress and write.

        Returns:
            int: Number of bytes written.

        Raises:
            CompressionError: If compression or writing fails.
        """
        ...
    def flush(self) -> None:
        """
        Flushes the internal buffer to disk.

        Raises:
            IOError: If flushing fails.
        """
        ...
    def close(self) -> None:
        """
        Closes the writer and flushes any remaining data.

        Raises:
            IOError: If flushing fails during close.
        """
        ...
    def __enter__(self) -> Self:
        """
        Context manager entry — returns self.

        Returns:
            FrameEncoderWriter: The writer instance itself.
        """
        ...
    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[Any],
    ) -> None:
        """
        Context manager exit — flushes and closes the writer.
        """
        ...

@overload
def open(
    filename: Union[str, os.PathLike],
    mode: Optional[Literal["wb", "wb|lz4"]] = None,
    info: Optional[FrameInfo] = None,
) -> Union[LZCompressionWriter]: ...
@overload
def open(
    filename: Union[str, os.PathLike],
    mode: Optional[Literal["rb", "rb|lz4"]] = None,
) -> Union[LZCompressionReader]: ...
