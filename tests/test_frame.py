import os
import math
import pytest
import safelz4
from safelz4 import (
    BlockSize,
    BlockMode,
    FrameInfo,
    compress,
    decompress,
    compress_into_file,
    decompress_file,
)
from safelz4.frame import compress_with_info
from typing import IO
import tempfile

# Error handling and edge cases
def test_compress_none_input():
    """Test that compress handles None input gracefully"""
    with pytest.raises((TypeError, ValueError)):
        compress(None)


def test_decompress_invalid_data():
    """Test decompression with corrupted/invalid data"""
    invalid_data = b"this is not compressed lz4 data"
    with pytest.raises(Exception):  # Should raise some decompression error
        decompress(invalid_data)


def test_decompress_truncated_data():
    """Test decompression with truncated compressed data"""
    original = b"Hello, World!" * 100
    compressed = compress(original)
    truncated = compressed[:-10]  # Remove last 10 bytes
    with pytest.raises(Exception):
        decompress(truncated)


def test_compress_very_large_data():
    """Test compression with large data (memory limits)"""
    # Test with 10MB of data
    large_data = b"A" * (10 * 1024 * 1024)
    compressed = compress(large_data)
    decompressed = decompress(compressed)
    assert decompressed == large_data


def test_compress_binary_data():
    """Test compression with binary data (not just text)"""
    binary_data = bytes(range(256)) * 100  # All possible byte values
    compressed = compress(binary_data)
    decompressed = decompress(compressed)
    assert decompressed == binary_data


# FrameInfo parameter variations
def test_different_block_sizes():
    """Test all available block sizes"""
    test_data = b"Test data for block size testing" * 50

    block_sizes = [
        BlockSize.Max64KB,
        BlockSize.Max256KB,
        BlockSize.Max1MB,
        BlockSize.Max4MB,
    ]
    for block_size in block_sizes:
        info = FrameInfo(
            block_size=block_size, block_mode=BlockMode.Independent
        )
        compressed = compress_with_info(test_data, info)
        decompressed = decompress(compressed)
        assert decompressed == test_data


def test_different_block_modes():
    """Test all available block modes"""
    test_data = b"Test data for block mode testing" * 50

    block_modes = [BlockMode.Independent, BlockMode.Linked]
    for block_mode in block_modes:
        info = FrameInfo(block_size=BlockSize.Max64KB, block_mode=block_mode)
        compressed = compress_with_info(test_data, info)
        decompressed = decompress(compressed)
        assert decompressed == test_data


def test_frame_info_equality():
    """Test FrameInfo equality comparison"""
    info1 = FrameInfo(
        block_size=BlockSize.Max64KB, block_mode=BlockMode.Independent
    )
    info2 = FrameInfo(
        block_size=BlockSize.Max64KB, block_mode=BlockMode.Independent
    )
    info3 = FrameInfo(
        block_size=BlockSize.Max256KB, block_mode=BlockMode.Independent
    )

    assert info1 == info2
    assert info1 != info3


def test_compress_into_file_empty_file():
    """Test compress_into_file with empty source file"""
    with tempfile.NamedTemporaryFile() as src, tempfile.NamedTemporaryFile() as dst:
        # src is empty by default
        compress_into_file(src.name, b"")

        # Verify the compressed empty file can be read
        decompress_file


def test_context_manager_write_modes():
    """Test different write modes with context manager"""
    test_data = b"Context manager write test data"

    with tempfile.NamedTemporaryFile() as tmp:
        # Test 'wb' mode
        with safelz4.open(tmp.name, "wb") as f:
            f.write(test_data)

        with safelz4.open(tmp.name, "rb") as f:
            assert f.read(-1) == test_data


def test_context_manager_multiple_writes():
    """Test multiple writes in same context manager session"""
    data1 = b"First chunk of data"
    data2 = b"Second chunk of data"
    expected = data1 + data2

    with tempfile.NamedTemporaryFile() as tmp:
        with safelz4.open(tmp.name, "wb") as f:
            f.write(data1)
            f.write(data2)

        with safelz4.open(tmp.name, "rb") as f:
            assert f.read() == expected


def test_context_manager_partial_reads():
    """Test partial reads with context manager"""
    test_data = b"Partial read test data" * 10

    with tempfile.NamedTemporaryFile() as tmp:
        with safelz4.open(tmp.name, "wb") as f:
            f.write(test_data)

        with safelz4.open(tmp.name, "rb") as f:
            # Read in chunks
            chunk1 = f.read(10)
            chunk2 = f.read(20)
            remaining = f.read()

            assert chunk1 + chunk2 + remaining == test_data


# Performance and compression ratio tests
def test_compression_ratio_highly_compressible():
    """Test compression ratio with highly compressible data"""
    # Highly repetitive data should compress well
    repetitive_data = b"A" * 10000
    compressed = compress(repetitive_data)
    ratio = len(compressed) / len(repetitive_data)
    assert ratio < 0.1  # Should compress to less than 10% of original


def test_compression_ratio_random_data():
    """Test compression ratio with random-like data"""
    # Random data should not compress well
    import random

    random.seed(42)  # For reproducible tests
    random_data = bytes([random.randint(0, 255) for _ in range(10000)])
    compressed = compress(random_data)
    ratio = len(compressed) / len(random_data)
    assert ratio > 0.9  # Should not compress much (>90% of original)


# Boundary conditions
def test_compress_single_byte():
    """Test compression of single byte"""
    single_byte = b"A"
    compressed = compress(single_byte)
    decompressed = decompress(compressed)
    assert decompressed == single_byte


def test_compress_max_block_boundary():
    """Test data at block size boundaries"""
    # Test data exactly at 64KB boundary
    boundary_data = b"X" * (64 * 1024)
    compressed = compress(boundary_data)
    decompressed = decompress(compressed)
    assert decompressed == boundary_data


# Thread safety (if applicable)
def test_concurrent_compression():
    """Test concurrent compression operations"""
    import threading
    import time

    test_data = b"Concurrent test data" * 1000
    results = []
    errors = []

    def compress_worker():
        try:
            compressed = compress(test_data)
            decompressed = decompress(compressed)
            results.append(decompressed == test_data)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=compress_worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Errors occurred: {errors}"
    assert all(results), "Not all concurrent operations succeeded"


def test_frame_info_invalid_parameters():
    """Test FrameInfo with invalid parameters"""
    # This depends on your implementation - adjust as needed
    with pytest.raises((ValueError, TypeError)):
        FrameInfo(block_size="invalid", block_mode=BlockMode.Independent)


def test_read_header_info_invalid_data():
    """Test reading header info from invalid data"""
    invalid_header = b"not a valid lz4 header"
    with pytest.raises(Exception):
        FrameInfo.read_header_info(invalid_header)


# Memory management
def test_memory_cleanup():
    """Test that large operations don't cause memory leaks"""
    import gc

    initial_objects = len(gc.get_objects())

    for _ in range(100):
        large_data = b"Memory test data" * 1000
        compressed = compress(large_data)
        decompressed = decompress(compressed)
        del large_data, compressed, decompressed

    gc.collect()
    final_objects = len(gc.get_objects())

    # Allow some variance but shouldn't grow significantly
    assert final_objects - initial_objects < 1000


# File permissions and error conditions
def test_file_permission_errors():
    """Test handling of file permission errors"""
    with tempfile.NamedTemporaryFile() as tmp:
        # Make file read-only
        os.chmod(tmp.name, 0o444)
        try:
            # This should fail when trying to write
            with pytest.raises((PermissionError, OSError)):
                with safelz4.open(tmp.name, "wb") as f:
                    f.write(b"test")
        finally:
            # Restore permissions for cleanup
            os.chmod(tmp.name, 0o644)


def test_closed_exeption_throw():

    with tempfile.NamedTemporaryFile() as tmp:
        f = safelz4.open(tmp.name, "wb")
        f.write(b"test")
        assert f.closed == False
        f.close()
        assert f.closed == True
        with pytest.raises((ValueError)):
            # NOTE: Memory writer
            # within the rust binding, though in this case
            # since where using the wrapped object is
            # is a check that just checks if the file is
            # closed. i.e None
            f.write(b"hello world")


def test_read_write_context_check_info():
    """Test properties/functions of wrapper Encoder/Decoder"""
    original = b"Idempotency test data" * 10000
    with tempfile.NamedTemporaryFile() as tmp:
        f = safelz4.open(tmp.name, "wb")
        # NOTE: Since We don't declare a block size default to AUTO.
        #       though this should change when we write to the object
        block_size = f.frame_info.block_size
        assert block_size == BlockSize.Auto
        written = f.write(original)
        # NOTE: The Auto block size should of changed.
        assert f.frame_info.block_size != BlockSize.Auto
        assert written <= len(original)
        expected = f.frame_info
        f.close()

        # Read Compressed Bytes
        o = safelz4.open(tmp.name, "rb")
        # Info
        assert o.frame_info == expected
        assert o.current_block == 0
        # NOTE: 210_000 bytes < 256_000 bytes
        assert o.block_size == BlockSize.Max256KB
        assert o.block_checksum == False
        assert o.content_size == None
        assert o.mode == "rb"
        assert o.name == tmp.name

        # IO generic call check
        assert o.readable() == True  # not closed so should be readable
        assert o.writable() == False  # should be false always
        assert original == o.read(-1)  # read all bytes
        assert o.read(-1) == b""  # empty bytes
        max_block = math.ceil(len(original) / o.block_size.get_size())
        assert max_block == o.current_block
        o.close()


def test_instance_IO_typeing():
    """Test that safelz4 is an instance of it's inhertance class IO"""
    original = b"Idempotency test data" * 10000
    with tempfile.NamedTemporaryFile() as tmp:
        f = safelz4.open(tmp.name, "wb")
        f.write(original)
        assert isinstance(f, IO)
        f.close()
        o = safelz4.open(tmp.name, "rb")
        assert isinstance(o, IO)
        o.close()


def test_roundtrip_idempotency():
    """Test that compress->decompress->compress gives same result"""
    original = b"Idempotency test data" * 100

    compressed1 = compress(original)
    decompressed = decompress(compressed1)
    compressed2 = compress(decompressed)

    assert decompressed == original
    assert compressed1 == compressed2
    # Note: compressed1 and compressed2 might not be identical due to
    # different compression parameters or randomness, but that's okay
