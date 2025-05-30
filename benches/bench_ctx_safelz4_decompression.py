import os
import pyperf
import safelz4
import lz4.frame
import io
from typing import Generator, Callable
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


def decompression_write_safelz4(file: tempfile.NamedTemporaryFile, chunk_size: int = 1024):
    with safelz4.open(file.name, "rb") as output:
            while _ := output.read(chunk_size):
                 ...
        

def benchmark_compression(name: str, _callable : Callable[[tempfile.NamedTemporaryFile, int], None]):
    filename = os.path.join(samples, name)
    
    if not os.path.exists(filename):
        print(f"Warning: File {filename} not found, skipping...")
        return
    
    with open(filename, "rb") as f :
        temp_file = tempfile.NamedTemporaryFile()
        safelz4.compress_into_file(temp_file.name, f.read(-1))
        py_runner.bench_func(f"ctx_compression_writer_{name}", _callable, temp_file)

def main():
    for name in AVAILABLE_FILES:
        benchmark_compression(name, decompression_write_safelz4)

if __name__ == "__main__":
    main()
