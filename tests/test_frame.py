import os
import pytest

import safelz4
from safelz4 import BlockSize, BlockMode, FrameInfo, compress, decompress, compress_file
from safelz4.frame import compress_with_info
import tempfile

pwd = os.path.dirname(os.path.abspath(__file__))
samples = os.path.join(pwd, "..", "benches", "samples")
FILE_1Kb = os.path.join(samples, "compression_1k.txt")


def test_compress_empty_frame():
    empty_string = b""
    _ = compress(empty_string)


def test_compress_regular():
    with open(FILE_1Kb, "rb") as file:
        output = file.read(-1)
        buffer = compress(output)
        reduc = 1 - (len(buffer) / len(output))
        print(reduc)
        assert reduc <= 1.0


def test_compress_with_info_default():
    with open(FILE_1Kb, "rb") as file:
        output = file.read(-1)
        info = FrameInfo.default()
        buffer = compress_with_info(output, info)
        reduc = 1 - (len(buffer) / len(output))
        assert reduc <= 1.0


def test_compare_read_bytes_buffer():
    with open(FILE_1Kb, "rb") as file:
        output = file.read(-1)
        expected = FrameInfo(
            block_size=BlockSize.Max64KB, block_mode=BlockMode.Independent
        )
        buffer = compress_with_info(output, FrameInfo.default())
        info = FrameInfo.read_header_info(buffer)
        assert expected == info


def test_decompress_empty_frame():
    empty_string = b""
    buffer = compress(empty_string)
    assert decompress(buffer) == empty_string


def test_decompress_regular():
    with open(FILE_1Kb, "rb") as file:
        expected = file.read(-1)
        info = FrameInfo(
            block_size=BlockSize.Max64KB, block_mode=BlockMode.Independent
        )
        buffer = compress_with_info(expected, info)

        output = decompress(buffer)
        assert output.decode("utf-8") == expected

def test_context_manager_decompression():
    tmp = tempfile.NamedTemporaryFile()
    length = 0
    expected = None
    with open(FILE_1Kb, "rb") as file:
        expected = file.read(-1)
        length = len(expected)
        _ = compress_file(tmp.name, expected)


    output = None
    with safelz4.open(tmp.name, "rb") as f:
        output = f.read(length)
    
    assert output == expected


def test_context_manager_roundtrip():
    tmp = tempfile.NamedTemporaryFile()
    length = 0
    expected = None

    file = open(FILE_1Kb, "rb")

    with safelz4.open(tmp.name, "wb") as in_f:
        expected = file.read(-1)
        length = in_f.write(expected)

    file.close()

    output = None
    with safelz4.open(tmp.name, "rb") as f:
        output = f.read(length)
    
    assert output == expected