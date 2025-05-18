from safelz4._safelz4_rs import _frame

__all__ = ["BlockMode", "BlockSize", "FrameInfo"]

BlockMode = _frame.BlockMode
BlockSize = _frame.BlockSize
FrameInfo = _frame.FrameInfo

deflate = _frame.deflate
deflate_file = _frame.deflate_file
deflate_file_with_info = _frame.deflate_file_with_info
deflate_with_info = _frame.deflate_with_info

enflate = _frame.enflate
enflate_file = _frame.enflate_file

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


