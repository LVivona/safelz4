import sys
import datetime
from collections import defaultdict

import atheris

with atheris.instrument_imports():
    import safelz4


EXCEPTIONS = defaultdict(int)
START = datetime.datetime.now()
DT = datetime.timedelta(seconds=30)

def TestDecompCorruptBlock(data): 
    global START

    if datetime.datetime.now() - START > DT:
        for e, n in EXCEPTIONS.items():
            print(e, n)
        START = datetime.datetime.now()



atheris.Setup(sys.argv, TestDecompCorruptBlock)
atheris.Fuzz()