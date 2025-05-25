
<p align="center">
  <picture>
    <img alt="safelz4" src="https://raw.githubusercontent.com/LVivona/safelz4/refs/heads/main/.github/assets/banner.png" style="max-width: 100%;">
  </picture>
</p>

<p align="center">
    <a href="https://github.com/LVivona/safelz4/blob/main/LICENCE.md"><img alt="GitHub" src="https://img.shields.io/badge/licence-MIT Licence-blue"></a>
    <!-- Uncomment when release to pypi -->
    <a href="https://pypi.org/project/safelz4/"><img alt="PyPI" src="https://img.shields.io/pypi/v/safelz4"></a>
    <a href="https://pypi.org/project/safelz4/"><img alt="Python Version" src="https://img.shields.io/pypi/pyversions/safelz4?logo=python"></a>
</p>

Python bindings for [lz4_flex](https://github.com/PSeitz/lz4_flex), the fastest pure-Rust implementation of the LZ4 compression algorithm.


## Installation

### Pip

You can install `safelz4` via the pip manager:

```python
pip install safelz4
```

### From source

For the sources, you need Rust

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Make sure it's up to date and using stable channel
rustup update
git clone https://github.com/LVivona/safelz4.git
cd safelz4
pip install setuptools_rust
pip install maturin
# install
pip install -e .
```

## Getting Started

### Block Format


<p align="center">
  <picture>
    <img alt="safelz4 block" src="https://raw.githubusercontent.com/LVivona/safelz4/refs/heads/main/.github/assets/block.png" style="max-width: 95%;">
  </picture>
</p>

The block format is suitable only for smaller chunks of data, as each block must be fully compressed or decompressed in memory. For larger data sequences, the frame format should be used instead, as it supports streaming and includes metadata for better handling of large-byte sequences. [specs](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md)

```python
import os
import sys
from typing import Union, Generator
from safelz4.block import compress_prepend_size, decompress_size_prepended

def chunk_blocks(filename : Union[os.PathLike, str], chunk_size : int = 1048576) -> Generator[bytes, None, None]:
    """compress read bytes into chunks blocks"""
    with open(filename, "rb") as f:
        while content := f.read(chunk_size):
            buffer = compress_prepend_size(content)
            yield buffer

# 1 Mb chunck
blocks = chunk_blocks("dickens.txt")

for block in blocks:
    output = decompress_size_prepended(buffer)
    sys.stdout.write(output.decode("utf-8"))
```

### Frame Format

<p align="center">
  <picture>
    <img alt="safelz4 frame" src="https://raw.githubusercontent.com/LVivona/safelz4/refs/heads/main/.github/assets/frame.png" style="max-width: 95%;">
  </picture>
</p>


Frames are containers that encapsulate a set of compressed blocks. Information about the blocks is stored both in the frame header and within the blocks themselves. Read more within the [specs](https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md)


```python
import safelz4

buffer = None
with open("dickens.txt", "rb") as file:
    buffer = file.read(-1)
    safelz4.compress_file("dickens.lz4", buffer)


with safelz4.open("dickens.lz4", "rb") as f:
   while content := f.read(100):
      print(content.decode("utf-8"))

```

## Licence

[MIT License](https://github.com/LVivona/safelz4/blob/main/LICENCE.md)