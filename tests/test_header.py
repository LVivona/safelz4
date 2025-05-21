import os
from safelz4._frame import (FLG_RESERVED_MASK, 
                            FLG_VERSION_MASK, 
                            FLG_SUPPORTED_VERSION_BITS,
                            FLG_INDEPENDENT_BLOCKS,
                            FLG_BLOCK_CHECKSUMS,
                            FLG_CONTENT_SIZE,
                            FLG_CONTENT_CHECKSUM,
                            FLG_DICTIONARY_ID,
                            BD_RESERVED_MASK,
                            BD_BLOCK_SIZE_MASK,
                            MAGIC_NUMBER_SIZE,
                            BD_BLOCK_SIZE_MASK_RSHIFT,
                            MIN_FRAME_INFO_SIZE,
                            LZ4F_LEGACY_MAGIC_NUMBER,
                            LZ4F_MAGIC_NUMBER)


from safelz4 import compress, FrameInfo, BlockMode, BlockSize, LZ4Exception
from xxhash import xxh32

pwd = os.path.dirname(os.path.abspath(__file__))
samples = os.path.join(pwd, "..", "benches", "samples")
FILE_1Kb = os.path.join(samples, "compression_1k.txt")

def get_magic_number(buffer: bytes) -> int:
    return int.from_bytes(buffer[:4], "little")

def test_header_default():
    # Read and compress the test file
    with open(FILE_1Kb, "r") as f:
        buffer = f.read().encode("utf-8")

    compressed = compress(buffer)
    
    # Now analyze the header of the compressed data
    if len(compressed) < MIN_FRAME_INFO_SIZE:
        raise LZ4Exception(f"Compressed output too small: {len(compressed)} bytes")
    
    # Check magic number
    magic_num = get_magic_number(compressed)
    
    if magic_num == LZ4F_LEGACY_MAGIC_NUMBER:
        print("Legacy frame format detected")
        return
    
    if magic_num in list(range(0x184D2A50, 0x184D2A5F)):
        raise LZ4Exception(f"Unexpected skippable frame")
    
    if magic_num != LZ4F_MAGIC_NUMBER:
        raise LZ4Exception(f"Wrong magic number, got 0x{magic_num:x}, expected 0x{LZ4F_MAGIC_NUMBER:x}")
    
    # Parse flag bytes
    flg_byte, bd_byte = compressed[4], compressed[5]
    
    if flg_byte & FLG_VERSION_MASK != FLG_SUPPORTED_VERSION_BITS:
        raise LZ4Exception(f"Unsupported version: {flg_byte & FLG_VERSION_MASK}")
    
    if flg_byte & FLG_RESERVED_MASK != 0 or bd_byte & BD_RESERVED_MASK != 0:
        raise LZ4Exception("Flag bytes reserved bits are set")
    
    # Determine block mode
    if flg_byte & FLG_INDEPENDENT_BLOCKS != 0:
        block_mode = BlockMode.Independent
    else:
        block_mode = BlockMode.Linked
    print(f"Block mode: {block_mode}")
    
    # Check checksums
    content_checksum = flg_byte & FLG_CONTENT_CHECKSUM != 0
    block_checksums = flg_byte & FLG_BLOCK_CHECKSUMS != 0
    print(f"Content checksum: {content_checksum}")
    print(f"Block checksums: {block_checksums}")
    
    # Determine block size
    block_size_code = (bd_byte & BD_BLOCK_SIZE_MASK) >> BD_BLOCK_SIZE_MASK_RSHIFT
    
    if block_size_code == 4:
        block_size = BlockSize.Max64KB
    elif block_size_code == 5:
        block_size = BlockSize.Max256KB
    elif block_size_code == 6:
        block_size = BlockSize.Max1MB
    elif block_size_code == 7:
        block_size = BlockSize.Max4MB
    elif block_size_code == 8:
        block_size = BlockSize.Max8MB
    else:
        raise LZ4Exception(f"Unsupported block size code: {block_size_code}")
    
    print(f"Block size: {block_size}")
    
    # Calculate current position in the header
    pos = 6  # After magic number and flag bytes
    
    # Check for content size
    content_size = None
    if flg_byte & FLG_CONTENT_SIZE != 0:
        if len(compressed) < pos + 8:
            raise LZ4Exception("Compressed data too small to contain content size")
        content_size = int.from_bytes(compressed[pos:pos+8], "little")
        pos += 8
        print(f"Content size: {content_size}")
    
    # Check for dictionary ID
    dict_id = None
    if flg_byte & FLG_DICTIONARY_ID != 0:
        if len(compressed) < pos + 4:
            raise LZ4Exception("Compressed data too small to contain dictionary ID")
        dict_id = int.from_bytes(compressed[pos:pos+4], "little")
        pos += 4
        print(f"Dictionary ID: {dict_id}")
    
    # Verify header checksum
    if len(compressed) < pos + 1:
        raise LZ4Exception("Compressed data too small to contain header checksum")
    
    expected_checksum = compressed[pos]
    header_data = compressed[4:pos]
    
    # Calculate checksum (right-shifted by 8 bits and keeping only the lowest byte)
    calculated_hash = (xxh32(header_data, seed=0).intdigest() >> 8) & 0xFF
    
    if calculated_hash != expected_checksum:
        raise LZ4Exception(f"Header checksum mismatch: expected {expected_checksum}, got {calculated_hash}")
    else:
        print("Header checksum verified successfully")
    
    print("Header validation completed successfully")
    
    # You can now read the compressed data frame info using the library's functionality 
    # and compare it with your manual parsing
    
    frame_info = FrameInfo.read_header_info(compressed)
    for byte in compressed[0:pos]:
        print(f"{bin(byte):0<8}", end=" ")
        

    assert frame_info.block_checksums == block_checksums
    assert frame_info.block_mode == block_mode
    assert block_size == frame_info.block_size
    assert frame_info.content_checksum == content_checksum
    assert frame_info.content_size == content_size
    print(f"\nLibrary parsed frame info: {frame_info}")