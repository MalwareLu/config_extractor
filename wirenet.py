# Malware.lu
import sys
from Crypto.Cipher import ARC4
 

crypted = [
                { 'name':'ConnectionString', 'adr': 0xf610, 'len': 0xff },
                { 'name':'ProxyString', 'adr': 0xf510, 'len': 0xff },
                { 'name':'Password', 'adr': 0xf4ec, 'len': 0x20  },
                { 'name':'HostId', 'adr': 0xf4c4, 'len': 0x10  },
                { 'name':'MutexName', 'adr': 0xf4b8, 'len': 0x8  },
                { 'name':'InstallPath', 'adr': 0xf434, 'len': 0x80  },
                { 'name':'StartupKeyName1', 'adr': 0xf420, 'len': 0x10  },
                { 'name':'StartupKeyName2', 'adr': 0xf3f8, 'len': 0x26  },
                { 'name':'KeyLoggerFileName', 'adr': 0xf374, 'len': 0x80  },
                { 'name':'BoolSettingsByte', 'adr': 0xf370, 'len': 0x3  },
                { 'name':'ConnectionType', 'adr': 0xf36c, 'len': 0x3  }
 ]
 

options = {
     'install_file': 1,
     'lock_file?': 4, # not sure
     'desktop_start': 8,
     'xinit_start': 16,
     'single_instance': 32,
     'keylogger': 64,
     'run_as_daemon': 128,
 }
 

def isOption(set_bytes, val):
     return ((val & int(set_bytes)) == val)
 

fp = open(sys.argv[1])
 fp.seek(0xf4d8, 0)
 key = fp.read(16)
 

for c in crypted:
     rc4 = ARC4.new(key)
     fp.seek(c['adr'])
     data = fp.read(c['len'])
     val = rc4.decrypt(data).split('\x00')[0]     print "%s: %s" % (c['name'], val)
 

   if c['name'] == 'BoolSettingsByte':
         for name, o in options.iteritems():
             print "%s: %s" % (name, isOption(val, o))

