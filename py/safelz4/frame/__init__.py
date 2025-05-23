import os
import io
from typing import Union, Optional, Literal
from safelz4._safelz4_rs import _frame, error

__all__ = [
    "FrameInfo",
    "BlockMode",
    "BlockSize",
    "decompress",
    "compress",
    "decompress_file",
    "compress_file",
    "compress_file_with_info",
    "compress_with_info",
    "is_framefile",
    "open",
]

# FrameInfo Header Classes
BlockMode = _frame.BlockMode
BlockSize = _frame.BlockSize
FrameInfo = _frame.FrameInfo

# IO Bound Classes
LZCompressionWriter = _frame.LZCompressionWriter
LZCompressionReader = _frame.LZCompressionReader

# Compression functions 
compress = _frame.compress
compress_file = _frame.compress_file
compress_file_with_info = _frame.compress_file_with_info
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

    except error.LZ4Exception:
        return False


def open(
    filename: Union[str, os.PathLike],
    mode: Optional[Literal["rb", "rb|lz4", "wb", "wb|lz4"]] = None,
    info: Optional[_frame.FrameInfo] = None,
) -> Union[_frame.LZCompressionReader, _frame.LZCompressionWriter]:
    """
    Returns a context manager for reading or writing lz4 frames to file.

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

    """
    if mode is None:
        return _frame.LZCompressionReader(filename)
    elif mode in ("rb", "rb|lz4"):
        return _frame.LZCompressionReader(filename)
    elif mode in ("wb", "wb|lz4"):
        return _frame.LZCompressionWriter(filename, info)
    else:
        raise ValueError(f"Unsupported mode: {mode}")
