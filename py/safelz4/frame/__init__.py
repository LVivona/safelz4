import os
import io
from typing import Union, Optional, Literal, Iterable
from typing_extensions import Buffer
from safelz4.error import LZ4Exception
from safelz4._safelz4_rs import _frame

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


class DecoderReaderWrapper(io.BufferedIOBase):
    """
    Wrapper that combines io.BufferedIOBase interface with FrameDecoderReader
    functionality. This makes the LZ4 decoder compatible with Python's
    standard I/O system.
    """

    def __init__(self, filename: str) -> None:
        # Initialize the parent FrameDecoderReader
        self._inner = _frame.FrameDecoderReader(filename)

    # BufferedIOBase required methods
    def readable(self) -> bool:
        """Returns True since this is a readable stream."""
        return not self._inner.closed

    def writable(self) -> bool:
        """Returns False since this is read-only."""
        return False

    def seekable(self) -> bool:
        """Returns True if seeking is supported."""
        return not self._inner.closed

    def tell(self) -> int:
        """Returns current position in block stream."""
        return self.offset()

    def seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        """
        Seek to position in the stream.

        Args:
            pos: Position to seek to
            whence: How to interpret pos (SEEK_SET, SEEK_CUR, SEEK_END)

        Returns:
            New absolute position

        Raises:
            ValueError: If the file is closed
            io.UnsupportedOperation: If seeking is not supported
        """
        if self.closed:
            raise ValueError("I/O operation on closed file")
        raise io.UnsupportedOperation("seek")

    def read(self, size: Optional[int] = -1) -> bytes:
        """
        Read and return up to size bytes.

        Args:
            size (`int`, **optional**, default to -1):
                Number of bytes to read. If -1 or None,
                read all remaining data.

        Returns:
            (`bytes`): block read from the stream return sized bytes of said
                       block

        Raises:
            (`ValueError`): If the file is closed
        """
        return self._inner.read(size)

    def read1(self, size: int = -1) -> bytes:
        """Read and return up to size bytes from the stream."""
        return self.read(size)

    def readinto(self, b: Buffer) -> Optional[int]:
        """
        Read data into a pre-allocated buffer.

        Args:
            b (`Buffer`):
                Buffer to read into (must support buffer protocol)

        Returns:
            (`Optional[int]`): Number of bytes read, or None if EOF

        Raises:
            (`ValueError`): If the file is closed
        """
        if self.closed:
            raise ValueError("I/O operation on closed file")

        data = self.read(len(b))
        if not data:
            return 0

        bytes_read = len(data)
        b[:bytes_read] = data
        return bytes_read

    def readinto1(self, b: Buffer) -> int:
        """Read data into buffer, single call to underlying raw stream."""
        result = self.readinto(b)
        return result if result is not None else 0


class EncoderWriterWrapper(io.BufferedIOBase):
    """
    Wrapper that combines io.BufferedIOBase interface with
    FrameEncoderWriter functionality. This makes the LZ4
    encoder compatible with Python's standard I/O system.
    """

    def __init__(
        self,
        filename: str,
        block_size: _frame.BlockSize = BlockSize.Auto,
        block_mode: _frame.BlockMode = BlockMode.Independent,
        block_checksums: Optional[bool] = None,
        dict_id: Optional[bool] = None,
        content_checksum: Optional[bool] = None,
        content_size: Optional[int] = None,
        legacy_frame: Optional[bool] = None,
    ) -> None:
        self._inner = _frame.FrameEncoderWriter(
            filename,
            block_size,
            block_mode,
            block_checksums,
            dict_id,
            content_checksum,
            content_size,
            legacy_frame,
        )

    # BufferedIOBase required methods
    def readable(self) -> bool:
        """Returns False since this is write-only."""
        return False

    def writable(self) -> bool:
        """Returns True since this is a writable stream."""
        return not self._inner.closed

    def seekable(self) -> bool:
        """
        Returns False since writing streams typically
        don't support seeking.
        """
        return False

    def tell(self) -> int:
        """Returns current position in the stream."""
        return self.offset()

    def write(self, data: Union[bytes, bytearray, memoryview]) -> int:
        """
        Write data to the stream.

        Args:
            data: Data to write (bytes-like object)

        Returns:
            Number of bytes written

        Raises:
            ValueError: If the file is closed
            TypeError: If data is not a bytes-like object
        """
        if self._inner.closed:
            raise ValueError("I/O operation on closed file")

        # Convert to bytes if necessary
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        elif not isinstance(data, bytes):
            raise TypeError(
                f"Expected bytes-like object, got {type(data).__name__}"
            )

        # Use the parent class's write method
        return self._inner.write(data)

    def writelines(
        self, lines: Iterable[Union[bytes, bytearray, memoryview]]
    ) -> None:
        """
        Write a list of bytes-like objects to the stream.

        Args:
            lines: Iterable of bytes-like objects

        Raises:
            ValueError: If the file is closed
        """
        if self._inner.closed:
            raise ValueError("I/O operation on closed file")

        for line in lines:
            self.write(line)

    def flush(self) -> None:
        """
        Flush the internal buffer to disk.

        Raises:
            ValueError: If the file is closed
        """
        if self.closed:
            raise ValueError("I/O operation on closed file")
        self._inner.flush()

    def close(self) -> None:
        """
        Close the stream and flush any remaining data.

        Raises:
            IOError: If flushing fails during close
        """
        if not self.closed:
            self._inner.close()


def open(
    filename: Union[str, os.PathLike],
    mode: Optional[Literal["rb", "rb|lz4", "wb", "wb|lz4"]] = None,
    block_size: _frame.BlockSize = BlockSize.Auto,
    block_mode: _frame.BlockMode = BlockMode.Independent,
    block_checksums: Optional[bool] = None,
    dict_id: Optional[bool] = None,
    content_checksum: Optional[bool] = None,
    content_size: Optional[int] = None,
    legacy_frame: Optional[bool] = None,
) -> Union[DecoderReaderWrapper, EncoderWriterWrapper]:
    """
    Returns a context manager for reading or writing lz4 frames.

    Example:

    ```
    import os
    import safelz4

    from typing import Union

    MEGABYTE = 1024 * 1024

    def chunk(filename : Union[os.PathLike, str], chunk_size : int = 1024):
        with open(filename, "rb") as f:
            while content := f.read(chunk_size):
                yield content

    chunk_size = 1024
    with safelz4.open("datafile.lz4", "wb") as file:
            for buf in chunk("datafile.txt", MEGABYTE)
                file.write(content)
    ```

    OR

    ```
    import safelz4

    chunk_size = 1024
    with safelz4.open("datafile.lz4", "rb") as file:
        while content := f.read(chunk_size):
            print(content)
    ```

    OR

    ```
    import safelz4

    chunk_size = 1024
    FILE = safelz4.open("datafile.lz4", "rb")

    while content := FILE.read(chunk_size):
        print(content)
    FILE.close()
    ```
    """
    if mode is None:
        return DecoderReaderWrapper(filename)
    elif mode in ("rb", "rb|lz4"):
        return DecoderReaderWrapper(filename)
    elif mode in ("wb", "wb|lz4"):
        return EncoderWriterWrapper(
            filename,
            block_size,
            block_mode,
            block_checksums,
            dict_id,
            content_checksum,
            content_size,
            legacy_frame,
        )
    else:
        raise ValueError(f"Unsupported mode: {mode}")
