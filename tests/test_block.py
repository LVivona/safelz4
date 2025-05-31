import os
import pytest
import safelz4
from safelz4.block import (
    compress,
    compress_into,
    compress_prepend_size,
    compress_prepend_size_with_dict,
    compress_with_dict,
    decompress,
    decompress_into,
    decompress_with_dict,
    decompress_prepend_size_with_dict,
    get_maximum_output_size,
)

pwd = os.path.dirname(os.path.abspath(__file__))
samples = os.path.join(pwd, "..", "benches", "samples")
FILE_1Kb = os.path.join(samples, "compression_1k.txt")


@pytest.fixture
def input_buffer() -> bytes:
    with open(FILE_1Kb, "rb") as f:
        return f.read()


def test_non_bytes_type_block_compression():
    """Raise TypeError when compressing a non-bytes input (e.g., None)."""
    with pytest.raises(TypeError):
        _ = compress(None)


def test_empty_block_compression():
    """Compress an empty byte string. Expect minimal valid output."""
    output = compress(b"")
    assert output == b"\x00"


def test_regular_block_compress(input_buffer):
    """Compress a 1KB file and validate size reduction and bounds."""
    output = compress(input_buffer)
    max_possible_size = get_maximum_output_size(len(input_buffer))
    reduc = 1 - (len(output) / len(input_buffer))
    assert reduc <= 1.0
    assert max_possible_size >= len(output)


def test_compression_into(input_buffer):
    """Compress a 1KB input directly into a preallocated buffer."""
    max_size = get_maximum_output_size(len(input_buffer))
    buffer = bytearray(max_size)
    size = compress_into(input_buffer, buffer)
    output = bytes(buffer[:size])
    reduc = 1 - (len(output) / len(input_buffer))
    assert reduc <= 1.0
    assert max_size >= len(output)


def test_compress_prepend_size(input_buffer):
    """Compress input and prepend the decompressed size to the output."""
    max_size = get_maximum_output_size(len(input_buffer))
    output = compress_prepend_size(input_buffer)
    reduc = 1 - (len(output) / len(input_buffer))
    assert reduc <= 1.0
    assert max_size >= len(output)


def test_regular_decompression_empty():
    """Decompress a compressed empty byte string."""
    empty_string = b""
    buffer = compress(empty_string)
    buffer = decompress(buffer, 1)
    assert buffer == empty_string


def test_regular_decompression(input_buffer):
    """Decompress a 1KB compressed file and validate its contents."""
    output = compress(input_buffer)
    output = decompress(output, len(input_buffer))
    assert input_buffer == output


def test_decompress_into(input_buffer):
    """Decompress into a preallocated buffer and validate contents."""
    cbuffer = compress(input_buffer)
    buffer = bytearray(len(input_buffer))
    size = decompress_into(cbuffer, buffer)
    output = bytes(buffer[:size])
    assert output == input_buffer


def test_decompress_into_type_raise(input_buffer):
    """Raise TypeError when decompressing into a non-bytearray (e.g., bytes)."""
    cbuffer = compress(input_buffer)
    buffer = bytes(len(input_buffer))  # Not a bytearray
    with pytest.raises(TypeError):
        _ = decompress_into(cbuffer, buffer)


def test_decompress_into_not_large_enough(input_buffer):
    """Raise error when output buffer is too small for decompression."""
    cbuffer = compress(input_buffer)
    buffer = bytearray(len(input_buffer) - 10)
    with pytest.raises(safelz4.error.LZ4BlockError):
        _ = decompress_into(cbuffer, buffer)


def test_decompress_size_prepended(input_buffer):
    """Decompress data with prepended original size (little-endian)."""
    buffer = compress_prepend_size(input_buffer)
    content_size = buffer[:4]
    size = int.from_bytes(content_size, "little")
    output = decompress(buffer[4:], size)
    assert output == input_buffer


def test_compression_with_dict(input_buffer):
    """Compress and decompress using a predefined dictionary."""
    ext_dict = b"\x00\x00\x00\x00"
    buffer = compress_with_dict(input_buffer, ext_dict)
    output = decompress_with_dict(buffer, len(input_buffer), ext_dict)
    assert output == input_buffer


def test_compression_prepend_size_with_dict(input_buffer):
    """Compress input with dictionary and prepend decompressed size."""
    ext_dict = b"\x00\x00\x00\x00"
    buffer = compress_prepend_size_with_dict(input_buffer, ext_dict)
    min_size = int.from_bytes(buffer[:4], "little")
    output = decompress_with_dict(buffer[4:], min_size, ext_dict)
    assert min_size == len(input_buffer)
    assert output == input_buffer


def test_decompression_prepend_size_with_dict(input_buffer):
    """Decompress size-prepended input using a custom dictionary."""
    buffer = compress_prepend_size_with_dict(input_buffer, b"\x01\x22\x02")
    output = decompress_prepend_size_with_dict(buffer, b"\x00\x00")
    assert output == input_buffer
