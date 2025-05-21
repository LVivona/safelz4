
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

Rust binding into python of the lz4 library [lz4_flex](https://github.com/PSeitz/lz4_flex) The Fastest LZ4 implementation in Rust.


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
git clone https://github.com/LVivona/safelz4
cd safelz4
pip install setuptools_rust
# install
pip install -e .
```

## Getting Started


### Frame Format
```python
from safelz4 import compress_file, open_frame

buffer = None
with open("dickens.txt", "r") as file:
    buffer = file.read(-1).encode("utf-8")

compress_file("dickens.lz4", buffer)

output = None
with open_frame("dickens.lz4") as f:
   output = f.decompress()

```

### Block Format
```python
from safelz4.block import compress_prepend_size, 

buffer = None
with open("dickens.txt", "r") as file:
    input_b = file.read(-1).encode("utf-8")
    buffer = compress_prepend_size(input_b)

output = decompress_size_prepended(buffer)
```

### Overview
