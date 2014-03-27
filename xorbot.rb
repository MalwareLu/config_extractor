#!/usr/bin/env ruby1.9.1
# Malware.lu

malwareFile = File.open(ARGV[0], 'r')
malwareFile.seek(0xee60, IO::SEEK_SET)
key = malwareFile.sysread(0x7)

file = File.open(ARGV[0], 'r')
file.seek(0x0, IO::SEEK_SET)
str =  file.sysread(File.stat(ARGV[0]).size)
i=0 

str.each_byte { |x|
  while i != 7 do
    x = x ^ key[i].ord
    i=i+1 
  end
  putc ~x
  i=0
} 
