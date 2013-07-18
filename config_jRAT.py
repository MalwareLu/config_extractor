#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
import sys,zipfile
from Crypto.Cipher import DES3
from curses.ascii import isprint

def printable(input):
    return ''.join(char for char in input if isprint(char))

def unzip_file(file, data):
     zfile = zipfile.ZipFile(file)
     i = 0
     for name in "key.dat", "config.dat":
         data.append(zfile.read(name))
         i+=1

if __name__ == "__main__":
     data=[]
     unzip_file(sys.argv[1], data)

     cipher = DES3.new(data[0])
     output = cipher.decrypt(data[1])
     print(printable(output).replace("SPLIT", "\n"))
