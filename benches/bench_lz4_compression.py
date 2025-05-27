import os
import pyperf
import lz4
import lz4.frame

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


def main():
    for name in AVAILABLE_FILES:
        filename = os.path.join(samples, name)
        
        if not os.path.exists(filename):
            print(f"Warning: File {filename} not found, skipping...")
            return
        
        output = open(filename, "rb").read(-1)
        py_runner.bench_func(f"compress_{name}", lz4.frame.compress, *[output])


if __name__ == "__main__":
    main()