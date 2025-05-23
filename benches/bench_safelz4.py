import os
import pyperf
import safelz4
import safelz4._frame

directory = os.path.dirname(os.path.abspath(__file__))
samples = os.path.join(directory, "samples")

# Available test files
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

def bench_func(name: str):
    """Benchmark compression and decompression for a given file."""
    filename = os.path.join(samples, name)
    
    if not os.path.exists(filename):
        print(f"Warning: File {filename} not found, skipping...")
        return
    
    with open(filename, "rb") as f:
        buffer = f.read(-1)
    
    py_runner.bench_func(f"compress_{name}", safelz4._frame.compress, *[buffer])
    output = safelz4.compress(buffer)
    py_runner.bench_func(f"decompress_{name}", safelz4._frame.decompress, *[output])
    del output
    del buffer

def main():
    for filename in AVAILABLE_FILES:
        bench_func(filename)


if __name__ == "__main__":
    main()