#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
from Crypto.Cipher import ARC4
import sys
import argparse
import magic
import base64
from urlparse import urlparse
import os
import os.path
import requests

def decode(data):
    key = data[:0x10]
    data = data[0x10:]
    # remove null byte in case
    data = data.strip('\x00')
    rc4 = ARC4.new(key)
    return rc4.decrypt(data)

def get_magic(data):
    try:
        return magic.from_buffer(data)
    except Exception, e:
        print e
        return ""

def extract_res(magictag, data, n = 0):
    i = -1
    res_end = 0
    while i < n:
        data = data[res_end:]
        res_start = data.index(magictag) + len(magictag)
        if res_start == None:
            break
        data = data[res_start:]
        res_end = data.index(magictag) + len(magictag)
        i += 1

    # out magic end
    data = data[:-0x8]
    return decode(data)

def decode_file(data):
    return decode(data)

def decode_config(data):
    data = data[-0x208:]
    return decode(data)

def decode_b64(data):
    data = data.strip('\n')
    data = data.replace('.', '+')
    data = base64.b64decode(data)
    out = decode(data)
    return out


def decode_network(url):
    uri_info = urlparse(url)
    uri = os.path.basename(uri_info.path)
    req = requests.get(url)
    data = req.text
    info = uri.split('_')
    user_info = base64.b64decode(info[0]).split('_')

    print "computer name: %s" % user_info[0]
    print "username: %s" % user_info[1]
    print "last modified (headers): %s" % req.headers['last-modified']
    print "-"*32
    lines = data.split('\n')
    for l in lines:
        tag = "ABCDEFGHIJKLMNOP"
        tag = l[:len(tag)]
        counter = l[len(tag):20]
        data = l[len(tag)+20:]
        out = decode_b64(data)
        print out

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Chinese decoder.')

    #parser.add_argument('filename', type=argparse.FileType(),
        #help='file to extract resource')
    parser.add_argument('filename', type=str,
        help='file to extract resource')

    parser.add_argument('-e', action='store_const', const='exe',
            dest='action', help='extract all resource of the dll (default)')
    parser.add_argument('-d', action='store_const', const='file',
            dest='action', help='decode encrypted file like .ini')
    parser.add_argument('-c', action='store_const', const='config',
            dest='action', help='extract config of the dll')
    parser.add_argument('-b', action='store_const', const='b64',
            dest='action', help='decode network b64')
    parser.add_argument('-n', action='store_const', const='network',
            dest='action', help='decode network')

    args = parser.parse_args()


    if args.action == 'network':
        decode_network(args.filename)
        sys.exit(1)


    fp = open(args.filename)
    #fp = args.filename
    data = fp.read()


    if args.action == 'file':
        out = decode_file(data)
        filename = "%s.dec" % fp.name
        print "write decoded file in %s (%s)" % \
            (filename, get_magic(out))
        open(filename, 'w').write(out)
    elif args.action == 'config':
        out = decode_config(data)
        print out
        filename = "%s.dec" % fp.name
        #print "write decoded file in %s (%s)" % \
            #(filename, get_magic(out))
        #open(filename, 'w').write(out)
    elif args.action == 'b64':
        out = decode_b64(data)
        print out
        filename = "%s.dec" % fp.name
        #print "write decoded file in %s (%s)" % \
            #(filename, get_magic(out))
        #open(filename, 'w').write(out)
    else:
        magictag = "\x7e\x21\x40\x23\x24\x25\x5e\x26"
        i = 0
        while True:
            try:
                out = extract_res(magictag, data, i)
                filename = "%s.%d.dec" % (fp.name, i)
                print "write decoded file in %s (%s)" % \
                    (filename, get_magic(out))
                open(filename, 'w').write(out)
                i += 1
            except Exception, e:
                #print e
                break

