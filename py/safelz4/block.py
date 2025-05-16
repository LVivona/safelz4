import safelz4._block as _block

from typing import Tuple

__all__ = [
    "compress",
    "compress_str_utf8_into",
    "compress_into",
    "compress_utf8_prepend_size",
    "compress_prepend_size",
    "decompress" "decompress_into",
    "decompress_size_prepended",
    "decompress_with_dict" "get_maximum_output_size",
]

get_maximum_output_size = _block.get_maximum_output_size


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


def compress_str_utf8(input: str) -> bytes:
    """
    Compress str that is utf-8 encodable into a block.

    Args:
        input (`str`)
            An arbitrary string buffer.

    Returns:
        `Tuple[int, bytes]` : size of the compressed, and the block.
    """
    buffer = input.encode("utf-8")
    return _block.compress(buffer)


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
    This is compatible with `decompress_size_prepended`.

    Args
        input : (`bytes`)
            fixed set of bytes to be compressed.

    Returns
        `bytes`:
            Compressed data with the uncompressed size prepended.
    """
    return _block.compress_prepend_size(input)


def decompress(input: bytes, min_size: int):
    """
    Decompress the input block bytes.

    Args:
        input (`bytes`)
            fixed set of bytes to be decompressed
        min_size (`int`):
            minimum possible size of uncompressed bytes

    Returns:
        `bytes`: decompressed repersentation of the compressed bytes.
    """
    return _block.decompress(input, min_size)


def decompress_into(input: bytes, output: bytearray) -> int:
    """
    Decompress input bytes into the provided output buffer. The output buffer must be preallocated with enough space for the uncompressed data.

    Args:
        input (`bytes`):
            Fixed set of bytes to be decompressed.
        output (`bytearray`):
            Mutable buffer to hold decompressed bytes.

    Returns:
        `int`: Number of bytes written to the output buffer.
    """
    return _block.decompress_into(input, output)


def decompress_size_prepended(input: bytes) -> bytes:
    """
    Decompress lz4 compressed block byte file format

    Args:
        input : (`bytes`)
            fixed set of bytes to be compressed.

    Returns:
        `bytes`: decompressed repersentation of the compressed bytes.
    """
    return _block.decompress_size_prepended(input)


def decompress_with_dict(input: bytes, ext_dict: bytes) -> bytes:
    """
    Decompress input bytes using a user-provided dictionary of bytes.

    Args:
        input (`bytes`):
            fixed set of bytes to be decompressed.
        ext_dict (`bytes`):
            Dictionary used for decompression.

    Returns:
        `bytes`: Decompressed data.
    """
    _block.decompress_with_dict(input, ext_dict)
