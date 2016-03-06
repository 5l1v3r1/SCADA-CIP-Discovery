#!/usr/bin/env python


"""
File: cipscan.py
Desc: Common Industrial Protocol Scanner UDP
Version: 1.0
Copyright (c) 2016 Ayushman Dutta
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version either version 3 of the License, 
or (at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import socket
import array
import struct
import optparse
from IPy import IP
import sys
from multiprocessing import Process,Queue
class CipScan(Process):

    def __init__(self,iprange,options):
        Process.__init__(self)
        self.iprange=iprange
        self.options=options
    def run(self):
        for ip in self.iprange:
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                s.settimeout(float(self.options.timeout)/float(100))
                msg = str(ip)+":"+str(self.options.port)
                print("Scanning"+" "+msg+"\n")
                conn=s.connect((str(ip),self.options.port))
                packet=struct.pack('24B',0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
                #packet=struct.pack(00 0c 29 a4 13 97 00 0f 73 03 8a 3f 08 00 45 00 00 71 b2 dc 00 00 80 06 f9 cd c0 a8 06 14 c0 a8 06 78 af 12 c0 8f 78 e7 63 d1 f2 da 4a a1 50 18 07 d0 f7 69 00 00 70 00 31 00 d7 03 46 ab 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 a1 00 04 00 0e 00 fe 80 b1 00 1d 00 3d fa cb 00 00 00 07 4d 00 04 02 5c 0b 4f 00 2d 33 00 07 00 00 3f 00 00 00 00 00 ff ff)
            except socket.error:
                msg="Failed to Connect\n"
                print(msg+"\n")
                s.close()
                break			
            try:			
			    s.send(packet)
            
			    print('Sent'+' '+packet)
            except socket.error:
                msg="Failed to Send\n"
                print(msg)
                s.close()
                break
            try:			
		       recv=s.recv(1024)
           
		       print('Received'+' '+recv+"\n")
            except socket.error:
                msg="Failed to Receive\n"
                print(msg+"\n")
                s.close()
                #break
            s.close()
        print("Scan has completed"+"\n")
        
        

def main():
    p = optparse.OptionParser(	description=' Finds CIP devices in IP range and determines Vendor Specific Information along with Internal private IP.\nOutputs in ip:port <tab> sid format.',
								prog='CipScan',
								version='CIP Scan 1.0',
								usage = "usage: %prog [options] IPRange")
    p.add_option('--port', '-p', type='int', dest="port", default=44818, help='CIP port DEFAULT:44814')
    p.add_option('--timeout', '-t', type='int', dest="timeout", default=500, help='socket timeout (mills) DEFAULT:500')
    options, arguments = p.parse_args()
    if len(arguments) == 1:
        print("Starting Common Industrial Protocol Scan"+"\n")
        i=""
        i=arguments[0]
        iprange=IP(i)
        q = Queue()
        for ip in iprange:
            print("Starting Multithreading"+"\n")
            p = CipScan(ip,options).start()
            q.put(p,False)
    else:
        
		p.print_help()
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "Scan canceled by user."
        print "Thank you for using CIP Scan"
    except :
        sys.exit()