import sys

import atheris

with atheris.instrument_imports():
    import safelz4


def TestDecompCorruptBlock(data: bytes):
    if len(data) >= 4:
        size = int.from_bytes(bytes=data[:4], byteorder="little")
        if size > 20_000_000:
            return

        try:
            safelz4._block.decompress_size_prepended(data)
        except safelz4.LZ4Exception:
            pass

        try:
            safelz4._block.decompress_with_dict(data, data)
        except safelz4.LZ4Exception:
            pass


atheris.Setup(sys.argv, TestDecompCorruptBlock)
atheris.Fuzz()
