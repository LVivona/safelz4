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
    """convert boolean logic to Literal char."""
    if compression:
        return "c"
    elif decompression:
        return "d"
    else:
        raise ValueError("No other mode is supported.")


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
        "  echo 'hello world' | %(prog)s -cb |"
        "  %(prog)s -db --size $(echo 'hello world' | wc -c)\n\n"
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


def main() -> int:
    """entry cli function"""
    args = _parse_argument()
    mode = _handle_args_mode(args.compress, args.decompress)

    # Check for invalid combinations
    if args.block and args.include_size and mode == "d" and args.size != 0:
        print(
            "Warning: '--size' is not needed when '--include-size' "
            "is used for block decompression.",
            file=_sys.stderr,
        )

    try:
        # Block mode
        if args.block:
            buffer = args.infile.read()
            if not buffer:
                raise ValueError("Input data is empty or could not be read.")

            output = None
            if mode == "c":
                if args.include_size:
                    output = safelz4.block.compress_prepend_size(buffer)
                else:
                    output = safelz4.block.compress(buffer)
            else:  # Decompression
                if args.include_size:
                    output = safelz4.block.decompress_size_prepended(buffer)
                else:
                    if args.size == 0:
                        raise ValueError(
                            "The '--size' argument is required for block "
                            "decompression when '--include-size' is"
                            " not specified."
                        )
                    output = safelz4.block.decompress(buffer, args.size)

            args.output.write(output)

        # Frame mode
        else:
            if args.buffer_size == -1:
                # One-shot operation for efficiency
                buffer = args.infile.read()
                if not buffer:
                    raise ValueError(
                        "Input data is empty or could not be read."
                    )

                output = None
                if mode == "c":
                    output = safelz4.compress(
                        buffer,
                    )
                else:
                    output = safelz4.decompress(buffer)

                args.output.write(output)
            else:
                # Streaming with a buffer for large files
                if mode == "c":
                    with safelz4.open(
                        args.output.name,
                        mode="wb",
                        block_size=args.block_size,
                        block_mode=safelz4.BlockMode.Independent
                        if args.block_independence
                        else safelz4.BlockMode.Linked,
                        content_checksum=args.content_checksum,
                        block_checksums=args.block_checksums,
                        legacy_frame=args.legacy_frame,
                    ) as comp_file:
                        while content := args.infile.read(args.buffer_size):
                            comp_file.write(content)
                else:
                    with safelz4.open(
                        args.infile.name, mode="rb"
                    ) as decomp_file:
                        while content := decomp_file.read(args.buffer_size):
                            args.output.write(content)

        # Final cleanup and file handling
        if args.dispose and args.infile.name != "<stdin>":
            _os.remove(args.infile.name)

        if mode == "c" and args.output.name != "<stdout>":
            # Check if output file has correct suffix and rename if necessary
            base, ext = _os.path.splitext(args.output.name)
            if ext != args.suffix:
                new_name = base + args.suffix
                args.output.close()  # Must close the file before renaming
                _os.rename(args.output.name, new_name)

    except (ValueError, safelz4.LZ4Exception, safelz4.error.LZ4BlockError) as e:
        print(f"Error: {e}", file=_sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"Error: File not found. {e}", file=_sys.stderr)
        return 1
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=_sys.stderr)
        return 1
    finally:
        # Ensure all file handles are closed
        if args.infile and args.infile.name != "<stdin>":
            args.infile.close()
        if args.output and args.output.name != "<stdout>":
            args.output.close()

    return 0


if __name__ == "__main__":
    _sys.exit(main())
