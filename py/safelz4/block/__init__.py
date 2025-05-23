from safelz4._safelz4_rs import _block

__all__ = [
    "compress",
    "compress_into",
    "compress_prepend_size",
    "compress_prepend_size_with_dict",
    "decompress",
    "decompress_into",
    "decompress_size_prepended",
    "decompress_with_dict",
    "decompress_prepend_size_with_dict",
    "get_maximum_output_size",
]

compress = _block.compress
compress_prepend_size = _block.compress_prepend_size
compress_into = _block.compress_into
compress_with_dict = _block.compress_with_dict
compress_prepend_size_with_dict = _block.compress_prepend_size_with_dict

decompress = _block.decompress
decompress_into = _block.decompress_into
decompress_size_prepended = _block.decompress_size_prepended
decompress_with_dict = _block.decompress_with_dict
decompress_size_prepended = _block.decompress_size_prepended
decompress_prepend_size_with_dict = _block.decompress_prepend_size_with_dict

get_maximum_output_size = _block.get_maximum_output_size
