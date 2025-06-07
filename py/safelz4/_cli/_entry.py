import os as _os
import sys as _sys

import argparse
from argparse import FileType

import safelz4

from typing import Literal


def simple_blocksize_type(value: str) -> safelz4.BlockSize:
    """Simple converter that only accepts enum names."""
    name_map = {
        "auto": safelz4.BlockSize.Auto,
        "64kb": safelz4.BlockSize.Max64KB,
        "256kb": safelz4.BlockSize.Max256KB,
        "1mb": safelz4.BlockSize.Max1MB,
        "4mb": safelz4.BlockSize.Max4MB,
        "8mb": safelz4.BlockSize.Max8MB,
    }

    lower_value = value.lower()
    if lower_value in name_map:
        return name_map[lower_value]

    raise argparse.ArgumentTypeError(
        f"Invalid block size: {value}. Valid options: "
        f"{', '.join(name_map.keys())}"
    )


def _handle_args_mode(
    compression: bool, decompression: bool
) -> Literal["c", "d"]:
    if compression:
        return "c"
    elif decompression:
        return "d"
    else:
        raise ValueError("no other mode is supported.")


def _parse_argument() -> argparse.Namespace:
    """Parse stdin to interface with safelz4 lib."""
    parser = argparse.ArgumentParser(
        prog="slz4",
        description="LZ4 compression and decompression utility",
        epilog="Block Examples:\n"
        "  %(prog)s -cboi output input.txt\n"
        "  %(prog)s -dboi input-copy.txt output\n"
        "  cat input.txt | %(prog)s -cbi\n"
        "  cat output | %(prog)s -dbi\b"
        "  echo 'hello world' | %(prog)s -cb | %(prog)s -db --size $(echo 'hello world' | wc -c)\n\n"
        "Frame Examples:\n"
        "  %(prog)s -df dickens.lz4 -o output.txt\n"
        "  %(prog)s -cf dickens.txt -o dickens.lz4\n"
        "  cat input.txt | %(prog)s -cfo input.txt.lz4",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "-c", "--compress", action="store_true", help="compress input file"
    )
    mode_group.add_argument(
        "-d", "--decompress", action="store_true", help="decompress input file"
    )

    file_format_group = parser.add_mutually_exclusive_group(required=True)
    file_format_group.add_argument(
        "-f", "--frame", action="store_true", help="Frame file format"
    )

    file_format_group.add_argument(
        "-b", "--block", action="store_true", help="Block file format"
    )

    frame_group = parser.add_argument_group("frame info option")

    frame_group.add_argument(
        "--block-size",
        type=simple_blocksize_type,
        default=safelz4.BlockSize.Auto,
        metavar="SIZE",
        help="block size: auto, 64kb, 256kb, 1mb, 4mb, 8mb (default: auto)",
    )

    frame_group.add_argument(
        "--block-independence",
        action="store_true",
        default=False,
        help="compress blocks independently (default: False)",
    )

    frame_group.add_argument(
        "--content-checksum", action="store_true", help="add content checksum"
    )
    frame_group.add_argument(
        "--block-checksums", action="store_true", help="add block checksums"
    )
    frame_group.add_argument(
        "--legacy-frame", action="store_true", help="add legacy frame"
    )

    block_group = parser.add_argument_group("block option")
    block_group.add_argument(
        "-i",
        "--include-size",
        action="store_true",
        default=False,
        help="handle preappend size of block.",
    )
    block_group.add_argument(
        "-s",
        "--size",
        type=int,
        default=0,
        help="If size is not included set decompression size",
    )

    # performance optional
    perf_group = parser.add_argument_group("frame performance options")
    perf_group.add_argument(
        "--buffer-size",
        type=int,
        default=-1,
        metavar="BYTES",
        help="I/O buffer size in bytes (default: -1)",
    )

    # file operation
    file_group = parser.add_argument_group("file handling")
    file_group.add_argument(
        "-p",
        "--dispose",
        action="store_true",
        default=False,
        help="remove input file after compression/decompression",
    )
    file_group.add_argument(
        "--suffix",
        default=".lz4",
        help="suffix for compressed files (default: .lz4)",
    )

    # infile files
    parser.add_argument(
        "infile",
        nargs="?",
        type=FileType("rb"),
        default=_sys.stdin.buffer,
        help="input file path (default: stdin)",
    )

    # output file
    parser.add_argument(
        "-o",
        "--output",
        nargs="?",
        type=FileType("wb"),
        default=_sys.stdout.buffer,
        help="output file path (defaults based on mode)",
    )

    args = parser.parse_args()
    return args


def main():
    """entry cli function"""
    try:
        args = _parse_argument()
        mode = _handle_args_mode(args.compress, args.decompress)

        if args.block:
            buffer = args.infile.read(-1)
            if len(buffer) > 1024 * 1024 * 8:
                print(
                    "Warning: Input is larger than 8MB.\n"
                    "Consider using frame compression for better"
                    " performance.",
                    file=_sys.stderr,
                )
            output = None
            if mode == "c":
                if args.include_size:
                    output = safelz4.block.compress_prepend_size(buffer)
                else:
                    output = safelz4.block.compress(buffer)
            else:
                if args.include_size:
                    output = safelz4.block.decompress_size_prepended(buffer)
                else:
                    output = safelz4.block.decompress(buffer, args.size)

            args.output.write(output)
        else:
            # Check if using stdin (not stdout)
            if args.output is _sys.stdout.buffer:
                buffer = args.infile.read(-1)
                output = None
                if mode == "c":
                    output = safelz4.compress(buffer)
                else:
                    output = safelz4.decompress(buffer)

                # write out to BinaryIO
                args.output.write(output)
            else:
                try:
                    file = None
                    if mode == "c":
                        # Compression: read from input file, write to compressed
                        # file.
                        block_size = args.block_size
                        block_mode = (
                            safelz4.BlockMode.Independent
                            if args.block_independence
                            else safelz4.BlockMode.Linked
                        )
                        block_checksums = args.block_checksums
                        content_checksum = args.content_checksum
                        legacy_frame = args.legacy_frame

                        file = safelz4.open(
                            args.output.name,
                            mode="wb",
                            block_size=block_size,
                            block_mode=block_mode,
                            block_checksums=block_checksums,
                            content_checksum=content_checksum,
                            legacy_frame=legacy_frame,
                        )
                        if args.buffer_size == -1:
                            buffer = args.infile.read(-1)
                            file.write(buffer)
                        else:
                            while content := args.infile.read(args.buffer_size):
                                file.write(content)
                    else:
                        # Decompression: read from compressed file, write to output
                        file = safelz4.open(args.infile.name, mode="rb")
                        if args.buffer_size == -1:
                            buffer = file.read(-1)
                            args.output.write(buffer)
                        else:
                            while content := file.read(args.buffer_size):
                                args.output.write(
                                    content
                                )

                finally:
                    # always close file.
                    file.close()

        # Handle file extension/suffix logic
        if args.output != _sys.stdout.buffer:
            output_file, ext = _os.path.splitext(args.output.name)
            suffix = args.suffix

            # Add proper suffix if not present
            if not ext == suffix:
                new_name = output_file + suffix
                _os.replace(args.output.name, new_name)

        # Remove input file if dispose flag is set
        if args.dispose and args.infile != _sys.stdin.buffer:
            _os.remove(args.infile.name)
    except Exception as e:
        print(e, file=_sys.stderr)
        return 1


if __name__ == "__main__":
    main()
