from ._safelz4_rs import __version__
import safelz4.block as block
import safelz4.frame as frame
import safelz4.error as error
from safelz4.frame import (
    BlockMode,
    BlockSize,
    FrameInfo,
    compress,
    decompress,
    decompress_file,
    compress_into_file,
    is_framefile,
    open,
)

# Base Exception error handling for lz4.
LZ4Exception = error.LZ4Exception

__all__ = [
    "__version__",
    "block",
    "frame",
    "BlockMode",
    "BlockSize",
    "FrameInfo",
    "LZ4Exception",
    "compress",
    "decompress",
    "is_framefile",
    "decompress_file",
    "compress_into_file",
    "open",
]
