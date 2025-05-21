from ._safelz4_rs import __version__, error
import safelz4.block as block
import safelz4.frame as frame
from safelz4.frame import compress, decompress, decompress_file, compress_file
from safelz4._frame import BlockMode, BlockSize, FrameInfo, open_frame

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
    "decompress_file",
    "compress_file",
    "open_frame",
]
