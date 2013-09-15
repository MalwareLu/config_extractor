#!/usr/bin/env python
# -*- coding:utf-8 -*-
# pandora2_config.py
#                  _                          _       
#  _ __ ___   __ _| |_      ____ _ _ __ ___  | |_   _ 
# | '_ ` _ \ / _` | \ \ /\ / / _` | '__/ _ \ | | | | |
# | | | | | | (_| | |\ V  V / (_| | | |  __/_| | |_| |
# |_| |_| |_|\__,_|_| \_/\_/ \__,_|_|  \___(_)_|\__,_|


import sys
import argparse


def find_package_info(pandora):
    pandora = pandora.read()
    return int(pandora.find("\x00\x6C\x00\x6F\x00\x77\x00\x00\x00"))


def print_conf(filename):

    malware = open(filename, "rb")

    malware.seek(find_package_info(malware), 0)

    result = {}
    parsed = malware.read().strip().split("##")
    result["ip address"] = parsed[0].replace("\x00\x6C\x00\x6F\x00\x77\x00\x00\x00", "")
    result["port"] = parsed[1]
    result["password"] = parsed[2]
    result["Server Directory"] = parsed[3]
    result["Server Filename"] = parsed[4]
    result["HKCU Startup key"] = parsed[5]
    result["Active Setup Registry Key"] = parsed[6]
    result["Install Server"] = parsed[7]
    result["Startup"] = parsed[8]
    result["ActiveX Startup"] = parsed[9]
    result["HKCU Startup"] = parsed[10]
    result["mutex"] = parsed[11]
    result["Usermode Unhooking"] = parsed[12]
    result["Melt Server"] = parsed[13]
    result["Activate Keylogger"] = parsed[14]
    result["Server ID"] = parsed[15]
    result["option1"] = parsed[16]
    result["Persistance"] = parsed[17]

    for key in result:
        print(key+" : "+str(result[key]))

    malware.close()


def main():


    parser = argparse.ArgumentParser(description = "Malware.lu Pandora2 config extractor")
    parser.add_argument('-d', '--decode', action='store_true',
        help="Print the configuration")
    parser.add_argument( dest="filename", 
        help="Pandora2 binary file")
    try:
        r = parser.parse_args()

        if r.decode:
            print_conf(r.filename)
        else:
            parser.print_help()

    except Exception as e:
        print >> sys.stderr, "Exception", e

if __name__ == '__main__':
    main()
