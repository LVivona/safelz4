from ._safelz4_rs import __version__, error
import safelz4.block as block
import safelz4.frame as frame
from safelz4.frame import deflate, enflate, enflate_file, deflate_file
from safelz4._frame import BlockMode, BlockSize

LZ4Exception = error.LZ4Exception

__all__ = [
    "__version__",
    "block",
    "frame",
    "BlockMode",
    "BlockSize",
    "LZ4Exception",
    "deflate",
    "enflate",
    "enflate_file",
    "deflate_file",
]
