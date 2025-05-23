from safelz4._safelz4_rs import _error

__all__ = [
    "LZ4Exception",
    "ReadError",
    "HeaderError",
    "CompressionError",
    "DecompressionError",
    "LZ4BlockError",
]

# Base Exception
LZ4Exception = _error.LZ4Exception

# LZ4 Frame Exception
ReadError = _error.ReadError
HeaderError = _error.HeaderError
CompressionError = _error.CompressionError
DecompressionError = _error.DecompressionError

# Block Exception
LZ4BlockError = _error.LZ4BlockError
