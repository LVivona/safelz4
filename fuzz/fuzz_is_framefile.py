import atheris
import sys

import safelz4
from safelz4.error import LZ4Exception
def fuzz_is_framefile(data: bytes):
    try:
        safelz4.is_framefile(data)
    except (LZ4Exception, ValueError, AttributeError):
        pass


def TestOneInput(data: bytes) -> None:
    fuzz_is_framefile(data)


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()