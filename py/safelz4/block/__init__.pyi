def compress(input: bytes) -> bytes:
    """
    Compress the input bytes using LZ4.

    Args:
        input (`bytes`):
            Fixed set of bytes to be compressed.

    Returns:
        (`bytes`): compressed LZ4 block format.
    """
    ...

def compress_prepend_size(input: bytes) -> bytes:
    """
    Compress the input bytes using LZ4 and prepend the original
    size as a little-endian u32. This is compatible with
    `decompress_size_prepended`.

    Args:
        input (`bytes`):
            Fixed set of bytes to be compressed.

    Returns:
        (`bytes`):
            compressed LZ4 block format with uncompressed
            size prepended.
    """
    ...

def compress_into(input: bytes, output: bytearray) -> int:
    """
    Compress all bytes of input into the output array
    assuming size its known.

    Args:
        input (`bytes`):
            Fixed set of bytes to be compressed.
        output (`bytearray`):
            Mutable buffer to hold combessed bytes.

    Returns:
        (`int`): size of the compressed bytes
    """
    ...

def compress_with_dict(input: bytes, ext_dict: bytes) -> bytes:
    """
    Compress the input bytes using a user-provided dictionary.

    Args:
        input (`bytes`):
            Fixed set of bytes to be compressed.
        ext_dict (`bytes`):
            A dictionary of bytes used for compression input.

    Returns:
        (`bytes`): decompressed bytes.
    """
    ...

def compress_prepend_size_with_dict(input: bytes, ext_dict: bytes) -> bytes:
    """
    Compress input bytes using the proved dict of bytes, size is pre-appended.

    Args:
        input (`bytes`):
            Fixed set of bytes to be compressed.
        ext_dict (`bytes`):
            Dictionary used for compress.
     Returns:
         (`bytes`): compressed data.
    """
    ...

def decompress(input: bytes, min_size: int) -> bytes:
    """
    Decompress the input block bytes.

    Args:
        input (`bytes`)
            Fixed set of bytes to be decompressed
        min_size (`int`):
            Minimum possible size of uncompressed bytes

    Returns:
        (`bytes`): decompressed bytes.
    """
    ...

def decompress_into(input: bytes, output: bytearray) -> int:
    """
    Decompress input bytes into the provided output buffer.
    The output buffer must be preallocated with enough space
    for the uncompressed data.

    Args:
        input (`bytes`):
            Fixed set of bytes to be decompressed.
        output (`bytearray`):
            Mutable buffer to hold decompressed bytes.

    Returns:
        (`int`): number of bytes written to the output buffer.
    """
    ...

def decompress_size_prepended(input: bytes) -> bytes:
    """
    Decompress input bytes that were compressed with the original
    size prepended. Compatible with `compress_prepend_size`.

    Args:
        input (`bytes`):
            Fixed set of bytes to be decompressed

    Returns:
        (`bytes`): decompressed data.
    """
    ...

def decompress_with_dict(input: bytes, min_size: int, ext_dict: bytes) -> bytes:
    """
    Decompress input bytes using a user-provided dictionary of
    bytes.

    Args:
        input (`bytes`):
            Fixed set of bytes to be decompressed.
        min_size (`int`):
            Minimum possible size of uncompressed bytes.
        ext_dict (`bytes`):
            Dictionary used for decompression.

    Returns:
        (`bytes`): decompressed data.
    """
    ...

def decompress_prepend_size_with_dict(input: bytes, ext_dict: bytes) -> bytes:
    """
    Decompress input bytes using a user-provided dictionary
    of bytes, size is already pre-appended.

    Args:
        input (`bytes`):
            Fixed set of bytes to be decompressed.
        ext_dict (`bytes`):
            Dictionary used for decompression.

    Returns:
         (`bytes`): decompressed data.
    """
    ...

def get_maximum_output_size(input_len: int) -> int:
    """
    Obtain the maximum output size of the block

    Args:
        input_len (`int`):
            Length of the bytes we need to allocate to compress
            into fixed buffer.
    Returns:
        (`int`):
            maximum possible size of the output buffer needs to be."""
    ...
