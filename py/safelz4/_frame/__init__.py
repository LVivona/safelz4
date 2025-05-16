from safelz4._safelz4_rs import _frame

__all__ = ["BlockMode", "BlockSize", "FrameInfo"]

BlockMode = _frame.BlockMode
BlockSize = _frame.BlockSize
FrameInfo = _frame.FrameInfo

deflate = _frame.deflate
deflate_file = _frame.deflate_file
deflate_file_with_info = _frame.deflate_file_with_info
enflate = _frame.enflate
enflate_file = _frame.enflate_file
