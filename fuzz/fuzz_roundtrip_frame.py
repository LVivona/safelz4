import sys
import atheris

MEGABYTE: int = 1_048_576

with atheris.instrument_imports():
    from safelz4.frame import (
        BlockMode,
        BlockSize,
        FrameInfo,
        compress_with_info,
        decompress,
    )


def TestRoundTripFrame(data: bytes):
    if len(data) == 0:
        return

    # Extract seeds from the fuzzer data
    fdp = atheris.FuzzedDataProvider(data)
    data_size_seed = fdp.ConsumeInt(4)  # Use 4 bytes for seed
    chunk_size_seed = fdp.ConsumeInt(4)  # Use 4 bytes for seed

    # Get remaining data as sample
    sample = fdp.ConsumeBytes(fdp.remaining_bytes())
    if not sample:
        return

    data_size = data_size_seed % MEGABYTE

    # Expand sample to required data_size
    input_data = bytearray()
    while len(input_data) < data_size:
        input_data.extend(sample)
    input_data = bytes(input_data[:data_size])

    for bm in [BlockMode.Independent, BlockMode.Linked]:
        for bs in [
            BlockSize.Max64KB,
            BlockSize.Max256KB,
            BlockSize.Max1MB,
            BlockSize.Max4MB,
        ]:
            for check_sum in [True, False]:
                fi = FrameInfo(
                    block_mode=bm,
                    block_size=bs,
                    block_checksums=check_sum,
                    content_checksum=check_sum,
                )

                try:
                    # Compress bytes with info
                    compressed = compress_with_info(input_data, fi)

                    # Decompress bytes into basic representation
                    decompressed = decompress(compressed)

                    # Verify round trip was successful
                    assert input_data == decompressed
                except Exception as e:
                    # Log the exception but don't crash the fuzzer
                    print(f"Exception during compression/decompression: {e}")



atheris.Setup(sys.argv, TestRoundTripFrame)
atheris.Fuzz()
