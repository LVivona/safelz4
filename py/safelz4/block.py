import safelz4._block as _block

from typing import Tuple


def compress(input: bytes) -> bytes:
    """
    Compress all bytes of input.

    Args:
        input (`bytes`):
            An arbitrary byte buffer to be compressed.

    Returns:
        `bytes`: lz4 compressed block.
    """
    return _block.compress(input)


def compress_str_utf8_into(input: str) -> Tuple[int, bytes]:
    """
    Compress str that is utf-8 encodable into a block.

    Args:
        input (`str`)
            An arbitrary string buffer.

    Returns:
        `Tuple[int, bytes]` : size of the compressed, and the block.
    """
    output = bytearray(len(input))
    buffer = input.encode("utf-8")
    return _block.compress_into(buffer, output), bytes(output)


def compress_into(input: bytes, output: bytearray) -> int:
    """
    Compress all bytes of input into the output array assuming size its known.

    Args:
        input (`bytes`):
            fixed set of bytes to be compressed.
        output (`bytearray`):
            Mutable buffer to hold decompressed bytes.

    Returns:
        `int` : size of the compressed bytes
    """
    return _block.compress_into(input, output)


def compress_utf8_prepend_size(input: str) -> bytes:
    """
    Compress all utf-8 compatible strings of input into output. The uncompressed size will be prepended as a little endian u32.

    Args:
        input (`str` that is uft-8 compatible):
            fixed set of `str` that is utf-8 encodable.

    Returns:
        `bytes`: compressed `block` format
    """
    try:
        buffer = input.encode("utf-8")
        return bytes(_block.compress_prepend_size(buffer))
    except UnicodeEncodeError:
        raise UnboundLocalError(
            f"input {input[:min(len(input), 5)]:>5} is not utf-8 encodable."
        )


def compress_prepend_size(input: bytes) -> Tuple[int, bytearray]:
    """
    Compress the input bytes using LZ4 and prepend the original size as a little-endian u32.
    This is compatible with decompress_size_prepended.

    Args
        input : (`bytes`)
            fixed set of bytes to be compressed.

    Returns
        `bytes`:
            Compressed data with the uncompressed size prepended.
    """
    return _block.compress_prepend_size(input)


def decompress_prepend_size(input: bytes) -> bytes:
    """
    Decompress lz4 compressed block byte file format

    Args:
        input : (`bytes`)
            fixed set of bytes to be compressed.

    Returns:
        `bytes`: decompressed repersentation of the compressed bytes.
    """
    return _block.decompress_size_prepended(input)
