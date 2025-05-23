class LZ4Exception(Exception):
    """Base exception for LZ4 Compression"""

    ...

class ReadError(LZ4Exception):
    """Raised when a lz4 is opened, that either cannot be handled by the safelz4 module or is somehow invalid."""

    ...

class HeaderError(LZ4Exception):
    """Raised when frame header is invalid or unreadable"""

    ...

class CompressionError(LZ4Exception):
    """Raised when a compression method is not supported or when the data cannot be decoded properly."""

    ...

class DeompressionError(LZ4Exception):
    """Raised when decompression method is not supported or when the data cannot be decoded properly."""

    ...

class LZ4BlockError(LZ4Exception):
    """Raise when block compression is invalid"""

    ...
