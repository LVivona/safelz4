import os

from typing import Union, Optional
import safelz4._frame as _frame
from safelz4._frame import FrameInfo, BlockMode, BlockSize

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
]


def decompress(input: bytes) -> bytes:
    """
    Decompresses a buffer of bytes using thex LZ4 frame format.

    Args:
        input (`bytes`):
            A byte containing LZ4-compressed data (in frame format).
            Typically obtained from a prior call to an `compress` or read from
            a compressed file `compress_file`.

    Returns:
        (`bytes`):
            The decompressed (original) representation of the input bytes.

    Example:

    ```python
    from safelz4 import decompress

    output = None
    with open("datafile.lz4", "r")  as file:
        buffer = file.read(-1).encode("utf-8")
        output = decompress(buffer)
    ```
    """
    return _frame.decompress(input)


def decompress_file(filename: Union[os.PathLike, str]) -> bytes:
    """
    Decompresses a buffer of bytes into a file using thex LZ4 frame format.

    Args:
        filename (`str` or `os.PathLike`):
            The filename we are loading from.

    Returns:
        (`bytes`):
            The decompressed (original) representation of the input bytes.

    Example:

    ```python
    from safelz4 import decompress

    output = decompress("datafile.lz4")
    ```

    """
    return _frame.decompress_file(filename)


def compress(input: bytes) -> bytes:
    """
    Compresses a buffer of LZ4-compressed bytes using the LZ4 frame format.

    Args:
        input (`bytes`):
            An arbitrary byte buffer to be compressed.
    Returns:
        (`bytes`):
             The LZ4 frame-compressed representation of the input bytes.

    Example:
    ```python
    from safelz4.frame import compress

    buffer = None
    with open("datafile.txt", "r") as file:
        output = file.read(-1).encode("utf-8")
        buffer = compress(output)

    # ...
    ```
    """
    return _frame.compress(input)


def compress_file(filename: Union[os.PathLike, str], input: bytes) -> None:
    """
    Compresses a buffer of bytes into a file using using the LZ4 frame format.

    Args:
        filename (`str` or `os.PathLike`):
            The filename we are saving into.
        input (`bytes`):
            un-compressed representation of the input bytes.

    Example:
    ```python
    from safelz4.frame import compress

    with open("datafile.txt", "r") as file:
        buffer = file.read(-1).encode("utf-8")
        compress_file("datafile.lz4", buf_f)

    ```

    Returns:
        (`None`)
    """
    return _frame.compress_file(filename, input)


def compress_file_with_info(
    filename: Union[os.PathLike, str],
    input: bytes,
    info: Optional[FrameInfo] = None,
) -> None:
    """
    Compresses a buffer of bytes into a file using using the LZ4 frame format,
    with more control on Block Linkage.

    Args:
        filename (`str`, or `os.PathLike`):
            The filename we are saving into.
        input (`bytes`):
            fixed set of bytes to be compressed.
        info (`FrameInfo, *optional*, defaults to `None``):
            The metadata for de/compressing with lz4 frame format.

    Returns:
        (`None`)
    """
    return _frame.compress_file_with_info(filename, input, info)


def compress_with_info(
    input: bytes,
    info: Optional[FrameInfo] = None,
) -> None:
    """
    Compresses a buffer of bytes into byte buffer using using
    the LZ4 frame format, with more control on Frame.

    Args:
        input (`bytes`):
            fixed set of bytes to be compressed.
        info (`FrameInfo, *optional*, defaults to `None``):
            The metadata for de/compressing with lz4 frame format.

    Returns:
        (`bytes`):
            The LZ4 frame-compressed representation of the input bytes.
    """
    return _frame.compress_with_info(input, info)
