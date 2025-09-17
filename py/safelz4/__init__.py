"""
SafeLZ4: High-Performance LZ4 Compression Library for Python

SafeLZ4 is a Python library that provides secure and efficient
bindings to the LZ4 compression algorithm. Built with Rust for optimal
performance and memory safety, it offers comprehensive compression solutions
for enterprise and high-throughput applications.

Overview:
    SafeLZ4 implements the LZ4 lossless compression algorithm with
    enhanced safety mechanisms and robust error handling. The library
    supports both low-level block operations and high-level frame
    operations, enabling developers to choose the appropriate
    abstraction level for their use case.

Architecture:
    The library is structured into three primary modules:

    * block - Direct block-level compression primitives for maximum performance
              and control over compression parameters
    * frame - Standards-compliant LZ4 frame format implementation with metadata
              support and streaming capabilities
    * error - Comprehensive exception hierarchy for precise error handling

Example Usage:
```

    >>> import safelz4
    >>>
    >>> # Frame-level compression
    >>> data = b"Sample data for compression" * 1000
    >>> compressed = safelz4.compress(data)
    >>> original = safelz4.decompress(compressed)
    >>>
    >>> # File operations with automatic format detection
    >>> with open("datafile.txt", "rb") as file:
    ...     buffer = file.read(-1)
    ...     safelz4.compress_into_file("datafile.lz4", buffer)
    >>>
    >>> output = safelz4.decompress_file("dataset.lz4")
    >>>
    >>> # Stream processing for large files
    >>> with safelz4.open("archive.lz4", "rb") as compressed_file:
    ...     while chunk := compressed_file.read(8192):
    ...         process_data(chunk)

```
Performance Characteristics:
    SafeLZ4 is optimized for scenarios requiring fast compression/decompression
    with moderate compression ratios. It excels in real-time data processing,
    network communication, and storage applications where speed is prioritized
    over maximum compression efficiency.
"""

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
    "error",
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
