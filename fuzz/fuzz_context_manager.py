import atheris
import sys
import tempfile

import safelz4
from safelz4.error import LZ4Exception

def fuzz_is_framefile(data: bytes):
    try:
        safelz4.is_framefile(data)
    except (LZ4Exception, ValueError, AttributeError):
        pass


def fuzz_wrapped_decoder(data: bytes):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".lz4") as tmp:
            tmp.write(data)
            tmp.flush()
            try:
                with safelz4.open(tmp.name, "rb") as f:
                    f.read()
                    f.readlines()
            except (LZ4Exception, ValueError, EOFError):
                pass
    except Exception:
        pass


def TestOneInput(data: bytes) -> None:
    fuzz_wrapped_decoder(data)


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
