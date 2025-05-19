import os
import pytest

from safelz4 import BlockSize, BlockMode, FrameInfo, deflate, enflate
from safelz4.frame import deflate_with_info

pwd = os.path.dirname(os.path.abspath(__file__))
samples = os.path.join(pwd, "..", "benches", "samples")
FILE_1Kb = os.path.join(samples, "compression_1k.txt")

def test_deflate_empty_frame():
    empty_string = b""
    _ = deflate(empty_string)


def test_deflate_regular():
    with open(FILE_1Kb, 'r') as file:
        output = file.read(-1)
        buffer = deflate(output.encode("utf-8"))
        reduc = 1 - (len(buffer) / len(output))
        print(reduc)
        assert reduc <= 1.0

def test_deflate_with_info_default():
    with open(FILE_1Kb, 'r') as file:
        output = file.read(-1)
        info = FrameInfo.default()
        buffer = deflate_with_info(output.encode("utf-8"), info)
        reduc = 1 - (len(buffer) / len(output))
        assert reduc <= 1.0

def test_compare_read_bytes_buffer():
    with open(FILE_1Kb, 'r') as file:
        output = file.read(-1)
        expected = FrameInfo(
            block_size=BlockSize.Max64KB,
            block_mode=BlockMode.Independent
        )
        buffer = deflate_with_info(output.encode("utf-8"), FrameInfo.default())
        info = FrameInfo.read(buffer)
        assert expected == info

def test_enflate_empty_frame():
    empty_string = b""
    buffer = deflate(empty_string)
    assert enflate(buffer) == empty_string


def test_enflate_regular():
    with open(FILE_1Kb, 'r') as file:
        expected = file.read(-1)
        info = FrameInfo(
            block_size=BlockSize.Max64KB,
            block_mode=BlockMode.Independent
        )
        buffer = deflate_with_info(expected.encode("utf-8"), info)
        
        output = enflate(buffer)
        assert output.decode("utf-8") == expected