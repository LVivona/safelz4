import os

import safelz4
import tempfile


cd = os.path.dirname(os.path.abspath(__file__))
filepath = os.path.join(cd, "..", "benches", "samples", "compression_1k.txt")

tmp = tempfile.NamedTemporaryFile()

# open file object
buffer = open(filepath, "rb")

# read the first 10 bytes for validation
expected = buffer.read(10)
buffer.seek(0)

# chunk size of the 
chunk_size = 8408
with safelz4.open(tmp.name, "wb") as output:
    while content := buffer.read(chunk_size):
        output.write(content)

# decompress the first 10 bytes
out = None
with safelz4.open(tmp.name, "rb") as file:
    out = file.read(10)
    
assert out == expected

