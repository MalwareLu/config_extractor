#!/usr/bin/env python
# darkcomet_config.py
# From https://code.google.com/p/alienvault-labs-garage/downloads/detail?name=extract_config_from_binary.py

import pefile
import sys
import random, base64, sys
from binascii import *

key = "#KCMDDC5#-890"


def rc4crypt(data, key):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))

    return ''.join(out)


pe = pefile.PE(sys.argv[1])

config = {"GENCODE": "", "MUTEX": "", "NETDATA": "", "PWD": "", "SID": ""}

rt_string_idx = [
    entry.id for entry in
    pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])

rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

for entry in rt_string_directory.directory.entries:
    if str(entry.name) in config.keys():
        data_rva = entry.directory.entries[0].data.struct.OffsetToData
        size = entry.directory.entries[0].data.struct.Size

        data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
        try:
            dec = rc4crypt(unhexlify(data), key)
            config[str(entry.name)] = dec
        except:
            print "Error during decrytion"

print config