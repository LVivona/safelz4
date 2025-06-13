import os
import safelz4.block as block

cd = os.path.dirname(os.path.abspath(__file__))
filepath = os.path.join(cd, "..", "benches", "samples", "compression_1k.txt")

MAX_UNCOMPRESSED_BLOCK = 240

buffer  = open(filepath, "rb")

blocks = []
# NOTE Reading from file 240 max bytes
#      per iteration so the max_len
#      uncompressed is at most 240.
while content := buffer.read(MAX_UNCOMPRESSED_BLOCK):
    buf = block.compress(content)
    blocks.append(buf)

# close file since unsued for the rest of the 
# program
buffer.close()

# pop blocks out of list and decompress them.
while output := blocks.pop(0):
    out_d = block.decompress(output, MAX_UNCOMPRESSED_BLOCK)
    print("Block:", out_d)
    if len(blocks) == 0:
        break
