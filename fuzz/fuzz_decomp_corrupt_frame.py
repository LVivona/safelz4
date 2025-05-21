import sys
import atheris

with atheris.instrument_imports():
    import safelz4


def TestDecompCorruptFrame(data: bytes):
    try:
        safelz4.compress(data)
    except safelz4.LZ4Exception:
        return

    # allocate memeory to dynamic byte array
    buffer = bytearray()

    # no prefic
    for prefix in [b"", b"\x04, \x22, \x4d, \x18"]:
        buffer.clear()
        buffer.extend(prefix)
        buffer.extend(data)
        try:
            safelz4.compress(buffer)
        except safelz4.LZ4Exception:
            return

    for preix in [
        [
            "\x04",
            "\x22",
            "\x4d",
            "\x18",
            "\x60",
            "\x40",
            "\x82",
        ]["\x04", "\x22", "\x4d", "\x18", "\x40", "\x40", "\xc0"]
    ]:
        try:
            buffer.clear()
            buffer.extend(prefix)
            buffer.extend(data)
            safelz4.compress(buffer)
            # use prefix then 2 valid blocks of data
            buffer.clear()
            buffer.extend(prefix)
            buffer.extend(int.to_bytes(len(data), length=4, byteorder="little"))
            buffer.extend(data)
            buffer.extend(int.to_bytes(len(data), length=4, byteorder="little"))
            buffer.extend(data)
            safelz4.compress(buffer)
        except safelz4.LZ4Exception as e:
            print(e, buffer)
            continue
        except OverflowError:
            return


atheris.Setup(sys.argv, TestDecompCorruptFrame)
atheris.Fuzz()
