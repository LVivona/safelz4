import sys
import atheris

with atheris.instrument_imports():
    import safelz4


def TestRoundTrip(data: bytes):
    compressed = safelz4.block.compress_prepend_size(data)
    decompressed = safelz4.block.decompress_size_prepended(compressed)
    assert data == decompressed


atheris.Setup(sys.argv, TestRoundTrip)
atheris.Fuzz()
