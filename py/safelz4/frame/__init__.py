import os
import io
from typing import Union, Optional, Literal, IO, List
from types import TracebackType
from safelz4.error import LZ4Exception
from safelz4._safelz4_rs import _frame

try:
    from typing import Self
except ImportError:
    # NOTE For Python < 3.12
    from typing_extensions import Self

__all__ = [
    "FrameInfo",
    "BlockMode",
    "BlockSize",
    "decompress",
    "compress",
    "decompress_file",
    "compress_into_file",
    "compress_into_file_with_info",
    "compress_with_info",
    "is_framefile",
    "open",
]

# FrameInfo Header Classes
BlockMode = _frame.BlockMode
BlockSize = _frame.BlockSize
FrameInfo = _frame.FrameInfo

# IO Bound Classes
FrameEncoderWriter = _frame.FrameEncoderWriter
FrameDecoderReader = _frame.FrameDecoderReader

# Compression functions
compress = _frame.compress
compress_into_file = _frame.compress_into_file
compress_into_file_with_info = _frame.compress_into_file_with_info
compress_with_info = _frame.compress_with_info

# Decompress functions
decompress = _frame.decompress
decompress_file = _frame.decompress_file

# Header constant flags
FLG_RESERVED_MASK = _frame.FLG_RESERVED_MASK
FLG_VERSION_MASK = _frame.FLG_VERSION_MASK
FLG_SUPPORTED_VERSION_BITS = _frame.FLG_SUPPORTED_VERSION_BITS

FLG_INDEPENDENT_BLOCKS = _frame.FLG_INDEPENDENT_BLOCKS
FLG_BLOCK_CHECKSUMS = _frame.FLG_BLOCK_CHECKSUMS
FLG_CONTENT_SIZE = _frame.FLG_CONTENT_SIZE
FLG_CONTENT_CHECKSUM = _frame.FLG_CONTENT_CHECKSUM
FLG_DICTIONARY_ID = _frame.FLG_DICTIONARY_ID

BD_RESERVED_MASK = _frame.BD_RESERVED_MASK
BD_BLOCK_SIZE_MASK = _frame.BD_BLOCK_SIZE_MASK
BD_BLOCK_SIZE_MASK_RSHIFT = _frame.BD_BLOCK_SIZE_MASK_RSHIFT

LZ4F_MAGIC_NUMBER = _frame.LZ4F_MAGIC_NUMBER
LZ4F_LEGACY_MAGIC_NUMBER = _frame.LZ4F_LEGACY_MAGIC_NUMBER

MAGIC_NUMBER_SIZE = _frame.MAGIC_NUMBER_SIZE
MIN_FRAME_INFO_SIZE = _frame.MIN_FRAME_INFO_SIZE
MAX_FRAME_INFO_SIZE = _frame.MAX_FRAME_INFO_SIZE
BLOCK_INFO_SIZE = _frame.BLOCK_INFO_SIZE


def is_framefile(
    name: Union[os.PathLike, str, bytes, io.BufferedReader]
) -> bool:
    """
    Return True if `name` is a valid LZ4 frame file or buffer, else False.

    Args:
        name (`str`, `os.PathLike`, `bytes`, or file-like object):
            A path to a file, a file-like object, or a bytes buffer to test.

    Returns:
        (`bool`): True if it's a valid LZ4 frame, False otherwise.
    """
    try:
        if isinstance(name, bytes):
            return _frame.FrameInfo.read_header_info(name)

        elif hasattr(name, "read"):
            pos = name.tell()
            name.seek(0)
            chunk = name.read(_frame.MAX_FRAME_INFO_SIZE)
            name.seek(pos)
            return _frame.FrameInfo.read_header_info(chunk)

        else:  # treat as path
            return _frame.is_framefile(name)

    except LZ4Exception:
        return False


class WrappedDecoderReader(IO[bytes]):
    """
    Wrapper that combines IO[bytes] interface with FrameDecoderReader
    functionality. This makes the LZ4 decoder compatible with Python's
    standard I/O system.
    """

    def __init__(
        self,
        filename: Union[os.PathLike, str],
        mode: Optional[Literal["rb", "rb|lz4"]] = None,
    ) -> None:
        self._inner = _frame.FrameDecoderReader(filename=filename, mode=mode)

    @property
    def mode(self) -> str:
        return self._inner.mode

    @property
    def name(self) -> str:
        """return name of the file."""
        return str(self._inner.name)

    @property
    def closed(self) -> bool:
        """Returns True if the file is closed."""
        return self._inner.closed

    @property
    def block_size(self) -> _frame.BlockSize:
        """
        Returns the block size used in the LZ4 frame.

        Returns:
            (`BlockSize`): Enum representing the block size.
        """
        return self._inner.block_size

    @property
    def content_size(self) -> Optional[int]:
        """
        Returns the content size specified in the LZ4 frame header.

        Returns:
            (`Optional[int]`): Content size if present, or None.
        """
        return self._inner.content_size

    @property
    def block_checksum(self) -> bool:
        """
        Checks if block checksums are enabled for this frame.

        Returns:
            (`bool`): True if block checksums are enabled, False otherwise.
        """
        return self._inner.block_checksum

    @property
    def frame_info(self) -> _frame.FrameInfo:
        """
        Returns a copy of the parsed frame header.

        Returns:
            (`FrameInfo`): Frame header metadata object.
        """
        return self._inner.frame_info

    @property
    def current_block(self) -> int:
        """
        Return the amounf of blocks that has been read.

        Returns:
            (`int`): current block number
        """
        return self._inner.current_block

    def readable(self) -> bool:
        """Returns True since this is a readable stream."""
        return not self._inner.closed

    def writable(self) -> bool:
        """Returns False since this is read-only."""
        return False

    def seekable(self) -> bool:
        """Returns False since LZ4 streams don't support seeking."""
        return False

    def tell(self) -> int:
        """Returns current position in block stream."""
        return self._inner.offset()

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
        if self.closed:
            raise ValueError("I/O operation on closed file")
        return self._inner.read(n)

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
        if self.closed:
            raise ValueError("I/O operation on closed file")

        line = b""
        bytes_read = 0

        while limit == -1 or bytes_read < limit:
            # Read one byte at a time to find newline
            chunk = self._inner.read(1)
            if not chunk:  # EOF reached
                break

            line += chunk
            bytes_read += 1

            # Check if we found a newline
            if chunk == b"\n":
                break

        return line

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
        if self.closed:
            raise ValueError("I/O operation on closed file")

        lines = []
        bytes_read = 0

        while hint == -1 or bytes_read < hint:
            line = self.readline()
            if not line:  # EOF reached
                break

            lines.append(line)
            bytes_read += len(line)

            # If hint is specified and we've read enough, break
            if hint != -1 and bytes_read >= hint:
                break

        return lines

    def close(self) -> None:
        """Close the stream."""
        if not self.closed:
            self._inner.close()

    def __enter__(self) -> Self:
        """Context manager entry"""
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """Context manager exit"""
        self._inner.__exit__(exc_type, exc_value, traceback)

    def __str__(self):
        return f"<frame.EncoderReader name={self._name}>"

    def __repr__(self):
        return f"<frame.EncoderReader name={self._name}>"


class WrappedEncoderWriter(IO[bytes]):
    """
    Wrapper that combines IO[bytes] interface with
    FrameEncoderWriter functionality. This makes the LZ4
    encoder compatible with Python's standard I/O system.
    """

    def __init__(
        self,
        filename: Union[os.PathLike, str],
        mode: Literal["wb", "wb|lz4"],
        block_size: _frame.BlockSize = BlockSize.Auto,
        block_mode: _frame.BlockMode = BlockMode.Independent,
        block_checksums: Optional[bool] = None,
        dict_id: Optional[int] = None,
        content_checksum: Optional[bool] = None,
        content_size: Optional[int] = None,
        legacy_frame: Optional[bool] = None,
    ) -> None:
        self._inner = _frame.FrameEncoderWriter(
            filename=filename,
            mode=mode,
            block_size=block_size,
            block_mode=block_mode,
            block_checksums=block_checksums,
            dict_id=dict_id,
            content_checksum=content_checksum,
            content_size=content_size,
            legacy_frame=legacy_frame,
        )

    @property
    def mode(self) -> str:
        return self._inner.mode

    @property
    def name(self) -> str:
        return str(self._inner.name)

    @property
    def closed(self) -> bool:
        return self._inner.closed

    @property
    def offset(self) -> int:
        return self._inner.offset

    @property
    def frame_info(self) -> _frame.FrameInfo:
        return self._inner.frame_info

    def readable(self) -> bool:
        """Returns False since this is write-only."""
        return False

    def writable(self) -> bool:
        """Returns True since this is a writable stream."""
        return not self.closed

    def seekable(self) -> bool:
        """
        Returns False since writing streams typically
        don't support seeking.
        """
        return False

    def tell(self) -> int:
        """Returns current position in the stream."""
        return self.offset

    def write(self, data: bytes) -> int:
        """
        Write data to the stream.

        Args:
            data (`bytes`): Data to write.

        Returns:
            (`int`): Number of bytes written.

        Raises:
            (`ValueError`): If the file is closed.
            (`TypeError`): If data is not a bytes-like object.
            (`LZ4Exception`):
                within FrameEncoderWriter rasied when the file is closed.
            (`CompressionError`):
                raised when a compression method is not supported or when
                the data cannot be encoded properly.
        """
        if self.closed:
            raise ValueError("I/O operation on closed file")

        if not isinstance(data, bytes):
            raise TypeError(
                f"Expected bytes-like object, got {type(data).__name__}"
            )

        return self._inner.write(data)

    def writelines(self, lines: List[bytes]) -> None:
        """
        Write a list of bytes-like objects to the stream.

        Args:
            lines (`List[bytes]`): Iterable of bytes-like objects.

        Raises:
            (`ValueError`):
                Raised when file is closed.
            (`TypeError`):
                Rasied if data is not a bytes-like object.
            (`LZ4Exception`):
                Rasied if within FrameEncoderWriter, when the file is closed.
            (`CompressionError`):
                Raised when a compression method is not supported or when
                the data cannot be encoded properly.
        """
        if self.closed:
            raise ValueError("I/O operation on closed file")

        for line in lines:
            self.write(line)

    def flush(self) -> None:
        """
        Flush the internal buffer to disk.

        Raises:
            (`LZ4Exception`):
                Rasied when the file is closed.
            (`IOError`):
                Raised when the file is unable to flush.
        """
        if self.closed:
            raise ValueError("I/O operation on closed file")
        self._inner.flush()

    def close(self) -> None:
        """
        Close the stream and flush any remaining data.

        Raises:
            (`IOError`):
                Raised when the file is unable to flush.
        """
        if not self.closed:
            self._inner.close()

    def __enter__(self) -> Self:
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """Context manager exit."""
        self._inner.__exit__(exc_type, exc_value, traceback)

    def __str__(self):
        return f"<frame.WrappedDecoderReader name={self.name}>"

    def __repr__(self):
        return f"<frame.WrappedDecoderReader name={self.name}>"


def open(
    filename: Union[str, os.PathLike],
    mode: Optional[Literal["rb", "rb|lz4", "wb", "wb|lz4"]] = None,
    block_size: _frame.BlockSize = BlockSize.Auto,
    block_mode: _frame.BlockMode = BlockMode.Independent,
    block_checksums: Optional[bool] = None,
    dict_id: Optional[int] = None,
    content_checksum: Optional[bool] = None,
    content_size: Optional[int] = None,
    legacy_frame: Optional[bool] = None,
) -> IO[bytes]:
    """
    Returns a context manager for reading or writing lz4 frames.

    Example:

    ```python
    import os
    import safelz4
    from typing import Union

    MEGABYTE = 1024 * 1024

    def chunk(filename: Union[os.PathLike, str], chunk_size: int = 1024):
        with open(filename, "rb") as f:
            while content := f.read(chunk_size):
                yield content

    # Writing LZ4 compressed data
    with safelz4.open("datafile.lz4", "wb") as file:
        for content in chunk("datafile.txt", MEGABYTE):
            file.write(content)
    ```

    OR

    ```python
    import safelz4

    # Reading LZ4 compressed data
    chunk_size = 1024
    with safelz4.open("datafile.lz4", "rb") as file:
        while content := file.read(chunk_size):
            print(content)
    ```

    OR

    ```python
    import safelz4

    # Reading without context manager
    chunk_size = 1024
    file = safelz4.open("datafile.lz4", "rb")
    try:
        while content := file.read(chunk_size):
            print(content)
    finally:
        file.close()
    ```
    """
    if mode is None:
        mode = "rb"

    if mode in ("rb", "rb|lz4"):
        return WrappedDecoderReader(filename, mode)
    elif mode in ("wb", "wb|lz4"):
        return WrappedEncoderWriter(
            filename,
            mode,
            block_size,
            block_mode,
            block_checksums,
            dict_id,
            content_checksum,
            content_size,
            legacy_frame,
        )
    else:
        raise ValueError(
            f"Unsupported mode: {mode}. Supported modes are: "
            "'rb', 'rb|lz4', 'wb', 'wb|lz4'"
        )
