import os

import safelz4
import tempfile


cd = os.path.dirname(os.path.abspath(__file__))
filepath = os.path.join(cd, "..", "benches", "samples", "compression_1k.txt")

tmp = tempfile.NamedTemporaryFile()


with open(filepath, "rb") as file:
    buf = file.read(-1)
    safelz4.compress_file(tmp.name, buf)

with safelz4.open(tmp.name, "rb") as file:
    while output := file.read(100):
        print(output)