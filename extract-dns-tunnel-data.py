#!/usr/bin/env python
"""
mkocbayi@gmail.com
Script createdto help extract DNS tunnel data from pcap.
Expects pcap to contain dns.id with 0x1337 and txt field with base64 encoding.
Output will be saved to file as binary.

TODO: Fix tshark crash, list mode of dns.id values in pcap
Wireshark filter  syntax http://kiminewt.github.io/pyshark/
"""
import sys
import logging
logging.basicConfig()
import os
import pyshark

script_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(script_path + '/libs')
from struct import *
from signal import *
import re
import argparse

settings = {
        'debug':0
    }

def read_pcap(pcap_file, display_filter_arg):
    '''
    Uses pyshark to read pcap file.
    arg1 pcap filename.
    arg2 wireshark display_filter e.g. dns.id==0x1337
    '''
    filtered_cap = pyshark.FileCapture(script_path + '/' + pcap_file, display_filter=display_filter_arg)
    if settings['debug']:
        filtered_cap.set_debug()
    for packet in filtered_cap:
        yield packet
    
def write_binary_file(filename,  newFileBytes):
    with open(script_path +'/'+ filename, 'ab+') as newFile:
        newFileByteArray = bytearray(newFileBytes)
        newFile.write(newFileByteArray)

def extract_data(stream):
    '''
    Expects stream to be dns tunnel data.
    Return data portion of tunnel data without command header.
    e.g. extract('FILE:AAAAA') return 'AAAA'
    '''
    searchObj = re.search( r'FILE:(.*)', stream, re.M|re.S)
    searchStart = re.search( r'FILE:START_STATE(.*)', stream, re.M|re.S)
    searchStop = re.search( r'FILE:STOP_STATE(.*)', stream, re.M|re.S)
    if searchStop:
        return
    if searchStart:
        return
    if searchObj:
       return searchObj.group(1)

def get_dns_data(pcap_filename):
    '''
    Returns the dns.txt portion of a list of packets from a pcap file.
    '''
    display_filter = 'dns.id==0x1337'
    for packet in read_pcap(pcap_filename, display_filter):
        yield packet.dns.txt

def main(argv):
    file_contents = ''
    # Read command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-r','--read_b64_file')
    parser.add_argument('-p','--read_pcap_file')
    parser.add_argument('-o','--write_file')
    parser.add_argument('--debug')
    args = parser.parse_args()
    if args.write_file:
        write_file = args.write_file
    if args.read_b64_file:
        filename = args.read_b64_file
    if args.read_pcap_file:
        pcap_filename = args.read_pcap_file
    if args.debug:
        settings['debug'] = 1
        print filename
    for dns_data in get_dns_data(pcap_filename):
        line = dns_data
        decoded_line = line.decode("base64").rstrip('\r\n')
        extracted_data = extract_data( decoded_line )
        if extracted_data:
            extracted_data = extracted_data.rstrip('\r\n')
            file_contents += extracted_data
            '''
            Write to output file here rather than at end of function is because
            pyshark complains with error and crashes.
            '''
            write_binary_file(write_file, extracted_data)

    if settings['debug']:
        for dns_data in get_dns_data(pcap_filename):
            line = dns_data
            decoded_line = line.decode("base64").rstrip('\r\n')
            extracted_data = extract_data( decoded_line )
            print "RAW"
            print decoded_line
            print "RAW_END"
            if extracted_data:
                print "b64"
                print line
                print "b64_END"
                print decoded_line
                print len(decoded_line)
                raw_input()
                print "CLEAN"
                extracted_data = extracted_data.rstrip('\r\n')
                file_contents += extracted_data
                print extracted_data, 
                print "CLEAN_END"
                import string
                print filter(lambda x: x in string.printable, extracted_data)
                print len(extracted_data)

if __name__ == "__main__":
    main(sys.argv[1:])
