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

    @staticmethod
    def from_buf_length(buf_len: int): ...
    def get_size(self) -> int: ...

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
            (`int`): Offset in bytes to the start of the first data block.
        """
        ...
    def content_size(self) -> Optional[int]:
        """
        Returns the content size specified in the LZ4 frame header.

        Returns:
            (`Optional[int]`): Content size if present, or None.
        """
        ...
    def block_size(self) -> BlockSize:
        """
        Returns the block size used in the LZ4 frame.

        Returns:
            (`BlockSize`): Enum representing the block size.
        """
        ...
    def block_checksum(self) -> bool:
        """
        Checks if block checksums are enabled for this frame.

        Returns:
            (`bool`): True if block checksums are enabled, False otherwise.
        """
        ...
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
    @property
    def closed(self) -> bool: ...
    def __enter__(self) -> Self:
        """
        Context manager entry — returns self.

        Returns:
            (`FrameDecoderReader`): The reader instance itself.
        """
        ...
    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[Any],
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
        (`IOError`): If the file cannot be opened for writing.
        (`CompressionError`): If writing something happens when into enocder.
    """

    def __new__(
        self, filename: str, info: Optional[FrameInfo] = None
    ) -> Self: ...
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
    def mode(self) -> Literal["wb", "rb"]:
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
    @property
    def closed(self) -> bool: ...
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
        traceback: Optional[Any],
    ) -> None:
        """
        Context manager exit — flushes and closes the writer.
        """
        ...

@overload
def open(
    filename: Union[str, os.PathLike],
    mode: Optional[Literal["rb", "rb|lz4", "wb", "wb|lz4"]] = None,
) -> Union[FrameDecoderReader, FrameEncoderWriter]: ...
@overload
def open(
    filename: Union[str, os.PathLike],
    mode: Optional[Literal["wb", "wb|lz4"]] = None,
    block_size: BlockSize = BlockSize.Auto,
    block_mode: BlockMode = BlockMode.Independent,
    block_checksums: Optional[bool] = None,
    dict_id: Optional[bool] = None,
    content_checksum: Optional[bool] = None,
    content_size: Optional[int] = None,
    legacy_frame: Optional[bool] = None,
) -> FrameEncoderWriter: ...
@overload
def open(
    filename: Union[str, os.PathLike],
    mode: Optional[Literal["rb", "rb|lz4"]] = None,
) -> FrameDecoderReader: ...
