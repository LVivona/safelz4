import os
import pyperf
import lz4.frame
import io
from typing import Generator
import tempfile

directory = os.path.dirname(os.path.abspath(__file__))
samples = os.path.join(directory, "samples")

AVAILABLE_FILES = [
    "compression_1k.txt",
    "compression_34k.txt",
    "compression_65k.txt", 
    "compression_66k_JSON.txt",
    "dickens.txt",
    "hdfs.json",
    "reymont.pdf",
    "xml_collection.xml"
]

py_runner = pyperf.Runner()

def chunk_compression(file: io.BufferedReader, chunk_size: int = 1024) -> Generator[bytes, None, None]:
    while content := file.read(chunk_size):
        yield content

def compression_write_lz4(file: tempfile.NamedTemporaryFile, chunks: Generator[bytes, None, None]):
    with lz4.frame.open(file.name, "wb") as output:
        for chunk in chunks:
            output.write(chunk)

def benchmark_compression(name: str, compressor_func):
    filename = os.path.join(samples, name)
    
    if not os.path.exists(filename):
        print(f"Warning: File {filename} not found, skipping...")
        return
    
    with open(filename, "rb") as f:
        output = chunk_compression(f)
        temp_file = tempfile.NamedTemporaryFile()
        py_runner.bench_func(f"ctx_compression_writer_{name}", compressor_func, temp_file, output)

def main():
    for name in AVAILABLE_FILES:
        benchmark_compression(name, compression_write_lz4)

if __name__ == "__main__":
    main()
