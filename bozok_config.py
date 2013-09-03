#!/usr/bin/env python
# -*- coding:utf-8 -*-
# cloger7_config.py
#                  _                          _       
#  _ __ ___   __ _| |_      ____ _ _ __ ___  | |_   _ 
# | '_ ` _ \ / _` | \ \ /\ / / _` | '__/ _ \ | | | | |
# | | | | | | (_| | |\ V  V / (_| | | |  __/_| | |_| |
# |_| |_| |_|\__,_|_| \_/\_/ \__,_|_|  \___(_)_|\__,_|


import sys,os,argparse

def find_package_info(bozok):
    bozok = bozok.read()
    return int(bozok.find("I\0N\0F\0"))

def print_conf(filename):

    bozok = open(filename, "rb")

    bozok.seek(find_package_info(bozok), 0)

    result = {}
    parsed = bozok.read().strip().split("|")
    parsed = [p.replace("\0", "") for p in parsed]
    result["Server ID"] = parsed[0]
    result["mutex"] = parsed[1]
    result["filename"] = parsed[2]
    result["startup key"] = parsed[3]
    result["extension name"] = parsed[4]
    result["password"] = parsed[5]
    result["Install Server"] = parsed[6]
    result["Startup Server"] = parsed[7]
    result["Visible Mode"] = parsed[8]
    result["option4"] = parsed[9]
    result["option5"] = parsed[10]
    result["port"] = parsed[11]
    result["ip address"] = parsed[12].replace("*", "")
    result["option6"] = parsed[13]
    if os.path.getsize(filename) > 100000:
        result["Include Extension"] = True

    for key in result:
        print(key+" : "+result[key])

def main():


    parser = argparse.ArgumentParser(description = "Malware.lu Bozok config extractor")
    parser.add_argument('-d', '--decode', action='store_true',
        help="Print the configuration")
    parser.add_argument( dest="filename", 
        help="Bozok binary file")
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
