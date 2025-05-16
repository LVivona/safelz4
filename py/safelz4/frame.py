import os

from typing import Union, Optional
import safelz4._frame as _frame
from safelz4._frame import FrameInfo, BlockMode, BlockSize

__all__ = [
    "FrameInfo",
    "BlockMode",
    "BlockSize",
    "enflate",
    "deflate",
    "enflate_file",
    "deflate_file",
    "deflate_file_with_info",
    "deflate_with_info",
]


def enflate(input: bytes) -> bytes:
    """
    Decompresses a buffer of bytes using thex LZ4 frame format.

    Args:
        input (`bytes`):
            A byte containing LZ4-compressed data (in frame format).
            Typically obtained from a prior call to an `deflate` or read from
            a compressed file `deflate_file`.

    Returns:
        `bytes`:
            The decompressed (original) representation of the input bytes.

    Example:
    ```python
    from safelz4.frame import enflate, deflate
    input_c = b'\x04"M\x18`@\x82O\x00\x00\x00\xff4hello world this is an example of text I would like to compresss ee\x02\x00&`eeeeee\x00\x00\x00\x00'

    output = enflate(input_c)
    expected = b"hello world this is an example of text I would like to compresss eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    assert expected == output
    ```
    """
    return _frame.enflate(input)


def enflate_file(filename: Union[os.PathLike, str]) -> bytes:
    """
    Decompresses a buffer of bytes into a file using thex LZ4 frame format.

    Args:
        filename (`str` or `os.PathLike`):
            The filename we are loading from.

    Returns:
        `bytes`:
            The decompressed (original) representation of the input bytes.

    """
    return _frame.enflate_file(filename)


def deflate(input: bytes) -> bytes:
    """
    Compresses a buffer of LZ4-compressed bytes using the LZ4 frame format.

    Args:
        input (`bytes`):
            An arbitrary byte buffer to be compressed.
    Returns:
        `bytes`:
             The LZ4 frame-compressed representation of the input bytes.

    Example:
    ```python
    from safelz4.frame import deflate
    input_d = b'\x04"M\x18`@\x82O\x00\x00\x00\xff4hello world this is an example of text I would like to compresss ee\x02\x00&`eeeeee\x00\x00\x00\x00'

    output = deflate(input_d)
    expected = b"hello world this is an example of text I would like to compresss eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    assert output == expected
    ```
    """
    return _frame.deflate(input)


def deflate_file(filename: Union[os.PathLike, str], input: bytes) -> None:
    """
    Compresses a buffer of bytes into a file using using the LZ4 frame format.

    Args:
        filename (`str` or `os.PathLike`):
            The filename we are saving into.
        input (`bytes`):
            un-compressed representation of the input bytes.

    Returns:
        `None`
    """
    return _frame.deflate_file(filename, input)


def deflate_file_with_info(
    filename: Union[os.PathLike, str],
    input: bytes,
    info: Optional[FrameInfo] = None,
) -> None:
    """
    Compresses a buffer of bytes into a file using using the LZ4 frame format, with more control on Block Linkage.

    Args:
        filename (`str`, or `os.PathLike`):
            The filename we are saving into.
        input (`bytes`):
            fixed set of bytes to be compressed.
        info (`FrameInfo, *optional*, defaults to `None``):
            The metadata for de/compressing with lz4 frame format.

    Returns:
        `None`
    """
    return _frame.deflate_file_with_info(filename, input, info)


def deflate_with_info(
    input: bytes,
    info: Optional[FrameInfo] = None,
) -> None:
    """
    Compresses a buffer of bytes into byte buffer using using the LZ4 frame format, with more control on Frame.

    Args:
        input (`bytes`):
            fixed set of bytes to be compressed.
        info (`FrameInfo, *optional*, defaults to `None``):
            The metadata for de/compressing with lz4 frame format.

    Returns:
        `bytes`:
            The LZ4 frame-compressed representation of the input bytes.
    """
    return _frame.deflate_with_info(input, info)
