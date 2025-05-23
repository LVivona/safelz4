import os
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


def test_empty_block_compression():
    output = compress(b"")
    assert output == b"\x00"


def test_regular_block_compress():

    with open(FILE_1Kb, "rb") as f:
        output = f.read(-1)
        output_c = compress(output)

        max_possible_size = get_maximum_output_size(len(output))
        reduc = 1 - (len(output_c) / len(output))
        # TEST
        # print(f"total reduction: {reduc:.2f}%")
        assert reduc <= 1.0
        assert max_possible_size >= len(output_c)


def test_compression_into():
    with open(FILE_1Kb, "rb") as f:
        stdin = f.read(-1)
        max_size = get_maximum_output_size(len(stdin))

        buffer = bytearray(max_size)
        size = compress_into(stdin, buffer)
        output = bytes(buffer[:size])
        reduc = 1 - (len(output) / len(stdin))
        # TEST
        # print(f"total reduction: {reduc:.2f}%")
        assert reduc <= 1.0
        assert max_size >= len(output)


def test_compress_prepend_size():
    with open(FILE_1Kb, "rb") as f:
        stdin = f.read(-1)
        max_size = get_maximum_output_size(len(stdin))

        output = compress_prepend_size(stdin)
        reduc = 1 - (len(output) / len(stdin))
        # TEST
        # print(f"total reduction: {reduc:.2f}%")
        assert reduc <= 1.0
        assert max_size >= len(output)


def test_regular_decompression_empty():
    empty_string = b""
    buffer = compress(empty_string)
    buffer = decompress(buffer, 1)
    assert buffer == empty_string


def test_regular_decompression():

    with open(FILE_1Kb, "rb") as file:
        stream_f = file.read(-1)

        cbuffer_f = compress(stream_f)

        output = decompress(cbuffer_f, len(stream_f))
        assert stream_f == output


def test_decompress_into():
    with open(FILE_1Kb, "rb") as file:
        stream_f = file.read(-1)

        cbuffer = compress(stream_f)

        buffer = bytearray(len(stream_f))
        size = decompress_into(cbuffer, buffer)
        output = bytes(buffer[:size])
        assert output == stream_f


def test_decompress_size_prepended():
    with open(FILE_1Kb, "rb") as file:
        stdin = file.read(-1)
        buffer = compress_prepend_size(stdin)

        # block size should be 32 unsigned integer
        # \x00\x00\x00\x00
        content_size = buffer[:4]
        size = int.from_bytes(content_size, "little")
        output = decompress(buffer[4:], size)

        assert output == stdin


def test_compression_with_dict():
    ext_dict = b"\x00\x00\x00\00"
    with open(FILE_1Kb, "rb") as file:
        stdin = file.read(-1)
        buffer = compress_with_dict(stdin, ext_dict)

        output = decompress_with_dict(buffer, len(stdin), ext_dict)
        assert output == stdin


def test_compression_prepend_size_with_dict():
    ext_dict = b"\x00\x00\x00\00"
    with open(FILE_1Kb, "rb") as file:
        expected = file.read(-1)
        buffer = compress_prepend_size_with_dict(expected, ext_dict)

        min_size = int.from_bytes(buffer[:4], "little")
        output = decompress_with_dict(
            buffer[4:],
            min_size,
            ext_dict
        )
        assert min_size == len(expected)
        assert expected == output


def test_decompression_prepend_size_with_dict():
    ext_dict = b"\x00\x00\x00\00"
    with open(FILE_1Kb, "rb") as file:
        expected = file.read(-1)
        buffer = compress_prepend_size_with_dict(expected, ext_dict)

        output = decompress_prepend_size_with_dict(
            buffer,
            ext_dict
        )
        assert expected == output