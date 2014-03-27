#!/usr/bin/env python
# darkcomet_config.py
# From https://bitbucket.org/r3shl4k1sh/spyeyeconfdec/src/7b33218efe66af844a1f6c18ea308caf08fbd818/SpyEyeConfDec.py

import os, sys, argparse

args = 0

def TakeArgs():
    global args

    parser = argparse.ArgumentParser(description = "Decrypt the config.bin file of common SpyEye Trojan.")
    parser.add_argument("EncryptedFile", type=argparse.FileType('rb'), help="The config.bin file path")
    parser.add_argument("DecryptedFile", type=argparse.FileType('wb'), help="The decrypted file path")
    #parser.add_argument("XORbyte", help="The XOR byte used to decrypt the file [usually 0x4C]")
    
    args = parser.parse_args()


def main():
    
    xor = int(0xC4)
    EncData = bytearray(args.EncryptedFile.read())
    
    counter = 0

    for idx, byte in reversed(list(enumerate(EncData))):
        if idx == 0:
            break
        var = byte ^ xor
        EncData[idx] = (var - EncData[idx -1]) & 0xFF
        
       
    args.DecryptedFile.write(EncData)

    args.DecryptedFile.close()
    args.EncryptedFile.close()


if __name__ == "__main__":
    TakeArgs()
    main()
