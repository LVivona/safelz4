import os
from safelz4.block import (
    compress,
    compress_str_utf8,
    compress_into,
    compress_utf8_prepend_size,
    compress_prepend_size,
    decompress,
    decompress_into,
    decompress_size_prepended,
    get_maximum_output_size,
)


pwd = os.path.dirname(os.path.abspath(__file__))
samples = os.path.join(pwd, "..", "benches", "samples")
FILE_1Kb = os.path.join(samples, "compression_1k.txt")

def test_empty_block_compression():
    output = compress(b"")
    assert output == b"\x00"


def test_regular_block_compress():

    with open(FILE_1Kb, "r") as f:
        output = f.read(-1)
        output_c = compress(output.encode("utf-8"))

        max_possible_size = get_maximum_output_size(len(output))
        reduc = 1 - (len(output_c) / len(output))
        # TEST
        # print(f"total reduction: {reduc:.2f}%")
        assert reduc <= 1.0
        assert max_possible_size >= len(output_c)


def test_str_utf8_into_compress():
    with open(FILE_1Kb, "r") as f:
        output = f.read(-1)
        buffer = compress_str_utf8(output)

        max_size = get_maximum_output_size(len(output))
        reduc = 1 - (len(buffer) / len(output))
        # TEST
        # print(f"total reduction: {reduc:.2f}%")
        assert reduc <= 1.0
        assert max_size >= len(buffer)


def test_compress_utf8_prepend_size():
    with open(FILE_1Kb, "r") as f:
        output = f.read(-1)
        buffer = compress_utf8_prepend_size(output)

        max_size = get_maximum_output_size(len(output))
        reduc = 1 - (len(buffer) / len(output))
        # TEST
        # print(f"total reduction: {reduc:.2f}%")
        assert reduc <= 1.0
        assert max_size >= len(buffer)


def test_compression_into():
    with open(FILE_1Kb, "r") as f:
        stdin = f.read(-1).encode("utf-8")
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
    with open(FILE_1Kb, "r") as f:
        stdin = f.read(-1).encode("utf-8")
        max_size = get_maximum_output_size(len(stdin))

        output = compress_prepend_size(stdin)
        reduc = 1 - (len(output) / len(stdin))
        # TEST
        # print(f"total reduction: {reduc:.2f}%")
        assert reduc <= 1.0
        assert max_size >= len(output)

# # ..End of Compression..


# # ..Begining of Decompression..
def test_regular_decompression_empty():
    empty_string = b""
    buffer = compress(empty_string)
    buffer = decompress(buffer, 1)
    assert buffer == empty_string


def test_regular_decompression(): 
    
    with open(FILE_1Kb, "r") as file:
        stream_f = file.read(-1).encode("utf-8")
        
        cbuffer_f = compress(stream_f)
        
        output = decompress(cbuffer_f, len(stream_f))
        assert stream_f == output

    
def test_decompress_into(): 
    with open(FILE_1Kb, "r") as file:
        stream_f = file.read(-1).encode("utf-8")

        cbuffer = compress(stream_f)

        buffer = bytearray(len(stream_f))
        size = decompress_into(cbuffer, buffer)
        output = bytes(buffer[:size])
        assert output == stream_f


def test_decompress_size_prepended(): 
        with open(FILE_1Kb, "r") as file:
            stream_f = file.read(-1).encode("utf-8")
            cbuffer = compress_prepend_size(stream_f)
            output  = decompress_size_prepended(cbuffer)
            assert output == stream_f

