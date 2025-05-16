from safelz4._safelz4_rs import _block

compress = _block.compress
compress_prepend_size = _block.compress_prepend_size
compress_into = _block.compress_into
compress_with_dict = _block.compress_with_dict

decompress = _block.decompress
decompress_into = _block.decompress_into
decompress_size_prepended = _block.decompress_size_prepended
decompress_with_dict = _block.decompress_with_dict

get_maximum_output_size = _block.get_maximum_output_size
