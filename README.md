
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
    safelz4.compress_into_file("dickens.lz4", buffer)


with safelz4.open("dickens.lz4", "rb") as f:
   while content := f.read(100):
      print(content.decode("utf-8"))

```

## Bechmarks

Benchmark results are available in the `benches` folder. We evaluated performance in two key scenarios:

   **Full byte availability**, where the entire buffer is accessible during compression and decompression.

  **Streamed access**, using reader and writer interfaces with chunked input.

  ###  Summary

  In full buffer scenarios, `lz4` generally performs well and occasionally outpaces `safelz4`, especially on larger files. However, `safelz4` still remained competitive, with close times.

  In reader/writer scenarios (chunked input, 1024 bytes), `safelz4` significantly outperforms `lz4`, consistently achieving more than 2x speed improvement in both compression and decompression.

### Streamed access ``(chunk 1024 bytes)``

| `open` Benchmark                                | safelz4 | lz4             |
|-------------------------------------------------|---------------|-----------------------|
| ctx_compression_writer_compression_1k.txt       | 8.84 us       | 22.5 us: 2.54x slower |
| ctx_compression_writer_compression_34k.txt      | 9.07 us       | 22.6 us: 2.49x slower |
| ctx_compression_writer_compression_65k.txt      | 9.18 us       | 23.0 us: 2.50x slower |
| ctx_compression_writer_compression_66k_JSON.txt | 9.18 us       | 23.1 us: 2.51x slower |
| ctx_compression_writer_dickens.txt              | 9.16 us       | 23.9 us: 2.61x slower |
| ctx_compression_writer_hdfs.json                | 9.21 us       | 22.9 us: 2.49x slower |
| ctx_compression_writer_reymont.pdf              | 9.26 us       | 22.9 us: 2.48x slower |
| ctx_compression_writer_xml_collection.xml       | 9.27 us       | 23.1 us: 2.49x slower |
| **Geometric mean**                              | **(ref)**     | **2.51x slower**      |

| `open` Benchmark                                       | safelz4 | lz4            |
|-------------------------------------------------|----------------|-----------------------|
| ctx_decompression_writer_compression_1k.txt       | 11.0 us        | 17.6 us: 1.59x slower |
| ctx_decompression_writer_compression_34k.txt      | 23.8 us        | 46.2 us: 1.94x slower |
| ctx_decompression_writer_compression_65k.txt      | 34.6 us        | 68.6 us: 1.98x slower |
| ctx_decompression_writer_compression_66k_JSON.txt | 27.1 us        | 61.9 us: 2.28x slower |
| ctx_decompression_writer_dickens.txt              | 4.11 ms        | 8.67 ms: 2.11x slower |
| ctx_decompression_writer_hdfs.json                | 1.77 ms        | 4.39 ms: 2.48x slower |
| ctx_decompression_writer_reymont.pdf              | 2.92 ms        | 5.74 ms: 1.97x slower |
| ctx_decompression_writer_xml_collection.xml       | 1.99 ms        | 3.97 ms: 2.00x slower |
| **Geometric mean**                              | **(ref)**      | **2.03x slower**      |

### Full byte availability Run(s) 
| `frame.compress` Benchmark                           | safelz4 | lz4                 |
|-------------------------------------|-----------|----------------------|
| compression_compression_1k.txt       | 829 ns    | 839 ns: 1.01x slower |
| compression_compression_34k.txt      | 26.3 us   | 32.5 us: 1.23x slower |
| compression_compression_65k.txt      | 49.9 us   | 60.1 us: 1.20x slower |
| compression_compression_66k_JSON.txt | 26.5 us   | 24.7 us: 1.07x faster |
| compression_dickens.txt              | 17.0 ms   | 15.9 ms: 1.07x faster |
| compression_hdfs.json                | 3.16 ms   | 2.63 ms: 1.20x faster |
| compression_reymont.pdf              | 12.3 ms   | 11.4 ms: 1.08x faster |
| compression_xml_collection.xml       | 4.58 ms   | 4.12 ms: 1.11x faster |
| **Geometric mean**                  | **(ref)** | **1.01x faster**      |

| `frame.decompress` Benchmark                           | safelz4 | lz4                |
|-------------------------------------|------------|----------------------|
| decompress_compression_1k.txt       | 612 ns     | 416 ns: 1.47x faster |
| decompress_compression_34k.txt      | 8.96 us    | 10.0 us: 1.12x slower |
| decompress_compression_65k.txt      | 15.4 us    | 17.1 us: 1.11x slower |
| decompress_compression_66k_JSON.txt | 9.45 us    | 8.04 us: 1.18x faster |
| decompress_dickens.txt              | 4.00 ms    | 2.13 ms: 1.88x faster |
| decompress_hdfs.json                | 1.50 ms    | 1.03 ms: 1.45x faster |
| decompress_reymont.pdf              | 2.42 ms    | 1.99 ms: 1.21x faster |
| decompress_xml_collection.xml       | 1.68 ms    | 1.19 ms: 1.41x faster |
| **Geometric mean**                  | **(ref)**  | **1.26x faster**      |


**NOTE**: All benchmarks were performed using python package `pypref`, on a system equipped with an Apple M4 Max processor and 36GB of unified memory.

## Acknowledgement

This project acknowledges the outstanding work of Yann Collet.

Special thanks also to the maintainers of the [lz4_flex](https://github.com/PSeitz/lz4_flex) Rust crate for providing a safe, pure-Rust implementation of LZ4 compression and decompression.

## Other Implementation

`LZ4` implementations, including:

| Python Library    | Build Status | Version | Licence | 
| -------- | ------- | ------- | ------- |
| [python-lz4](https://github.com/python-lz4/python-lz4) | [![Build Status](https://github.com/python-lz4/python-lz4/actions/workflows/build_dist.yml/badge.svg)](https://github.com/python-lz4/python-lz4/actions/workflows/build_dist.yml)| ![](https://img.shields.io/pypi/v/lz4) | ![PyPI - License](https://img.shields.io/pypi/l/lz4)



## Licence

[MIT License](https://github.com/LVivona/safelz4/blob/main/LICENCE.md)