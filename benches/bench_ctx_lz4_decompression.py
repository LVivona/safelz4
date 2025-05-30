import os
import pyperf
import lz4.frame
from typing import Callable
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
    with lz4.frame.open(file.name, "rb") as output:
            while _ := output.read(chunk_size):
                 ...
        

def benchmark_compression(name: str, _callable : Callable[[tempfile.NamedTemporaryFile, int], None]):
    filename = os.path.join(samples, name)
    
    if not os.path.exists(filename):
        print(f"Warning: File {filename} not found, skipping...")
        return
    temp_file = tempfile.NamedTemporaryFile()
    with open(filename, "rb") as f :
        with lz4.frame.open(temp_file.name, "wb") as output: 
            output.write(f.read(-1))
        py_runner.bench_func(f"ctx_compression_writer_{name}", _callable, temp_file)

def main():
    for name in AVAILABLE_FILES:
        benchmark_compression(name, decompression_write_safelz4)

if __name__ == "__main__":
    main()
