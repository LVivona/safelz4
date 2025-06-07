import subprocess
import os
import pytest
import tempfile
from pathlib import Path

pwd = os.path.dirname(os.path.abspath(__file__))
samples = os.path.join(pwd, "..", "benches", "samples")
FILE_1Kb = os.path.join(samples, "compression_1k.txt")

# Test data constant
TEST_TEXT = b"This is test data for compression testing. " * 100


@pytest.mark.parametrize("block_mode", ["-b"])
def test_compress_and_decompress_file(block_mode):
    """Test round-trip compression and decompression via CLI."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        output_file = tmp_path / "output.slz4"
        input_file = FILE_1Kb
        
        with open(output_file, "wb") as stdout:
            try:
                # Compress
                result = subprocess.run(
                    ["slz4", "-c", block_mode, "-i", str(input_file)],
                    stdout=stdout,
                    check=True,
                )
                print(f"Compression stdout: {result.stdout}")
                print(f"Compression stderr: {result.stderr}")
                print(f"Output file exists: {output_file.exists()}")
                if output_file.exists():
                    print(f"Output file size: {output_file.stat().st_size}")
                
                assert output_file.exists(), f"Output file was not created: {output_file}"
                assert output_file.stat().st_size > 0, f"Output file is empty: {output_file}"

                # Decompress
                result = subprocess.run(
                    ["slz4", "-d", "-i", block_mode, str(output_file)],
                    check=True,
                    capture_output=True,
                    text=True
                )
                print(f"Decompression stdout: {result.stdout}")
                print(f"Decompression stderr: {result.stderr}")
                
                with open(FILE_1Kb, "r") as file:
                    assert result.stdout == file.read()

            except Exception:
                raise


def test_block_compress_with_include_size():
    """Test block compression with --include-size and decompression using it."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        input_file = tmp_path / "input.txt"
        output_file = tmp_path / "output.slz4"
        
        # Write test data to input file
        input_file.write_bytes(TEST_TEXT)
        print(f"Input file created: {input_file}, size: {len(TEST_TEXT)}")
        
        with open(output_file, "wb") as stdout:
            result = subprocess.run(
                ["slz4", "-c", "-b", "--include-size", str(input_file)],
                stdout=stdout,
                check=True,
            )
            print(f"Compression result: stdout='{result.stdout}', stderr='{result.stderr}'")
            print(f"Output file exists: {output_file.exists()}")
        
        result = subprocess.run(
            ["slz4", "-d", "-b", "--include-size", str(output_file)],
            check=True,
            capture_output=True,
        )
        print(f"Decompression result: stdout length={len(result.stdout) if result.stdout else 0}")
        assert result.stdout == TEST_TEXT


def test_block_decompress_with_manual_size():
    """Test block decompression with manual --size when not using include-size."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        input_file = tmp_path / "input.txt"
        output_file = tmp_path / "output.slz4"
        
        # Write test data to input file
        input_file.write_bytes(TEST_TEXT)
        print(f"Input file created: {input_file}, size: {len(TEST_TEXT)}")
        
        with open(output_file, "wb") as stdout:
            result = subprocess.run(
                ["slz4", "-c", "-b", str(input_file)],
                stdout=stdout,
                check=True,
            )
            print(f"Compression result: stdout='{result.stdout}', stderr='{result.stderr}'")
            print(f"Output file exists: {output_file.exists()}")
        
        result = subprocess.run(
            ["slz4", "-d", "-b", "--size", str(len(TEST_TEXT)), str(output_file)],
            check=True,
            capture_output=True,
        )
        print(f"Decompression result: stdout length={len(result.stdout) if result.stdout else 0}")
        assert result.stdout == TEST_TEXT


def test_frame_options_blocksize():
    """Test frame compression with non-default block size."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        input_file = tmp_path / "input.txt"
        output_file = tmp_path / "output.slz4"
        
        # Write test data to input file
        input_file.write_bytes(TEST_TEXT)
        print(f"Input file created: {input_file}, size: {len(TEST_TEXT)}")
        
        with open(output_file, "wb") as stdout:
            result = subprocess.run(
                [
                    "slz4", "-c", "-f", "--block-size", "256kb",
                    "--content-checksum", "--block-checksums", "--block-independence",
                    str(input_file),
                ],
                stdout=stdout,
                check=True,
            )
            print(f"Compression result: stdout='{result.stdout}', stderr='{result.stderr}'")
            print(f"Output file exists: {output_file.exists()}")
        
        result = subprocess.run(
            ["slz4", "-d", "-f", str(output_file)],
            check=True,
            capture_output=True,
        )
        print(f"Decompression result: stdout length={len(result.stdout) if result.stdout else 0}")
        assert result.stdout == TEST_TEXT


def test_stdin_stdout_roundtrip():
    """Test stdin to stdout compression and decompression."""
    compress = subprocess.run(
        ["slz4", "-c", "-f"],
        input=TEST_TEXT,
        stdout=subprocess.PIPE,
        check=True,
    )
    decompress = subprocess.run(
        ["slz4", "-d", "-f"],
        input=compress.stdout,
        stdout=subprocess.PIPE,
        check=True,
    )
    assert decompress.stdout == TEST_TEXT


def test_missing_required_flags():
    """Test that required flags raise errors."""
    result = subprocess.run(
        ["slz4"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert "error" in result.stderr.lower()
    assert result.returncode != 0