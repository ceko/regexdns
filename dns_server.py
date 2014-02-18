#!/usr/bin/env python

import sys
import socket
import fcntl
import struct
import os
import re
import time

# DNSQuery class from http://code.activestate.com/recipes/491264-mini-fake-dns-server/
class DNSPacket(object):
    def __init__(self, data):
        self.data = data

    #16-bit identifier
    @property
    def ID(self):
        return struct.unpack("!h", self.data[0:2])[0]
    
    #1-bit field specifying whether this is a query or a response
    @property
    def QR(self):
        return ord(self.data[2]) >> 7 & 1
    
    #four-bit field specifying the kind of query
    @property
    def OPCODE(self):
        return ord(self.data[2]) >> 3 & 15
    
    #authoritative answer, only used in responses
    @property
    def AA(self):
        return ord(self.data[2]) >> 2 & 1
    
    #was the message truncated?
    @property
    def TC(self):
        return ord(self.data[2]) >> 1 & 1
    
    #recursion desired?
    @property
    def RD(self):
        return ord(self.data[2]) & 1
    
    #recursion available?
    @property
    def RA(self):
        return ord(self.data[2]) >> 7 & 1
    
    #reserved for future use
    @property
    def Z(self):
        return 0
    
    #error code, none should be set in the response
    @property
    def RCODE(self):
        return ord(self.data[3]) & 15

    #number of entries in the question section
    @property
    def QDCOUNT(self):
        return struct.unpack("!h", self.data[4:6])[0]

    #number of entries in the question section
    @property
    def ANCOUNT(self):
        return struct.unpack("!h", self.data[6:8])[0]

    #number of name server resource records
    @property
    def NSCOUNT(self):
        return struct.unpack("!h", self.data[8:10])[0]

    #number of resource records in additional records
    @property
    def ARCOUNT(self):
        return struct.unpack("!h", self.data[10:12])[0]

    @property
    def QNAME(self):        
        qname_offset = 12 #domain name starts here        
        domain_name = ''
        while(ord(data[qname_offset]) != 0): #domain name is terminated with a 0            
            segment_length = ord(self.data[qname_offset])            
            domain_name+='.' + self.data[qname_offset+1:qname_offset+segment_length+1]
            qname_offset+=segment_length+1
            
        return domain_name

    @property
    def QTYPE(self):
        return struct.unpack("!h", self.data[-4:-2])[0]

    @property
    def QTYPE_AS_STRING(self):
        qtype = self.QTYPE
        map = {
            1: 'A',
            15: 'MX'
        }
        return map.get(qtype, 'Unknown') 

    @property
    def QCLASS(self):
        return struct.unpack("!h", self.data[-2:])[0]

class DNSRequest(DNSPacket):
    pass
        
class DNSResponse(DNSPacket):
    RCODE_NO_ERROR = 0
    RCODE_FORMAT_ERROR = 1
    RCODE_SERVER_FAILURE = 2
    RCODE_NAME_ERROR = 3
    RCODE_NOT_IMPLEMENTED = 4
    RCODE_REFUSED = 5
    
    def __init__(self, dns_request, response_ip, ttl=1, *args, **kwargs):
        self.response_ip = response_ip
        self.ttl = ttl
        super(DNSResponse, self).__init__(dns_request.data, *args, **kwargs)
    
    def to_bytestring(self):
        packet = ''
        #add id
        packet += struct.pack('!h', self.ID)
        
        #qr/opcode/aa/tc/rd
        current_byte = 0
        #this is a response, AR will always be 1
        current_byte = current_byte | 128
        current_byte = current_byte | self.OPCODE << 3
        current_byte = current_byte | self.AA << 2
        current_byte = current_byte | self.TC << 1
        current_byte = current_byte | self.RD        
        packet += chr(current_byte)
        
        #ra/z/rcode
        current_byte = 0
        #recursion is never available
        #z is always 0
        if self.response_ip == '0.0.0.0':
            current_byte = current_byte | self.RCODE_NAME_ERROR
        else:
            current_byte = current_byte | self.RCODE_NO_ERROR
        packet += chr(current_byte)
        
        #counts
        packet += struct.pack('!h', self.QDCOUNT)
        #will have an answer to all the questions, as long as there's only one!
        packet += struct.pack('!h', self.QDCOUNT)
        packet += '\x00\x00\x00\x00' #nscount and arcount
                
        original_qname = self.data[12:-4]
        packet += original_qname
                
        packet += struct.pack('!h', self.QTYPE)
        packet += struct.pack('!h', self.QCLASS)
                
        packet += '\xc0\x0c' #pointer to the domain name        
        packet += '\x00\x01\x00\x01' #response type       
        
        ttl = 1 #32-bit integer (unsigned)
        packet += struct.pack('!i', ttl)
        
        response_length = 4 #4 byte ip address
        packet += struct.pack('!h', response_length)
        
        response = ''.join([chr(int(p)) for p in self.response_ip.split('.')])
        packet += response
        
        return packet

class DNSQuery:
    def __init__(self, data):
        self.request=DNSRequest(data)
        
    def get_response(self, ip, ttl=1):        
        self.response = DNSResponse(self.request, ip, ttl)
        packet = self.response.to_bytestring()
        
        return packet

resolvers = []
def resolve_ip(domain_name):
    for resolver in resolvers:
        if resolver.get('regex').match(domain_name):
            print 'Match found for ' + domain_name + ' with regex ' + resolver.get('regex_raw')
            return resolver.get('ip')
        
    print domain_name + ' not in hosts.txt file, resolving normally...'    
        
    #ip didn't exist, try to get it    
    fallback_ip = '' 
    try:
        fallback_ip = socket.gethostbyname(domain_name.lstrip('.'))
    except Exception, e:
        print "Couldn't find IP for " + domain_name
        fallback_ip = '0.0.0.0'
        
    return fallback_ip
if __name__ == '__main__':  
    try:
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.bind(('',53))
    except Exception, e:
        print "Failed to create socket on UDP port 53, check for conflict or adjust permissions:", e
        sys.exit(1)
    
    try:
        with open('hosts.txt') as file:
            line = file.readline()
            while line:                
                if line.strip().startswith('#'): 
          	    continue

                if "\t" in line:
                    ip, host_regex = line.strip().split("\t", 1)
                    print 'Loaded rule: {0} -> {1}'.format(host_regex, ip)
                    resolvers.append({
                        'regex_raw': host_regex.strip("\t"),
                        'regex': re.compile(host_regex.strip("\t"), re.IGNORECASE),
                        'ip': ip.strip("\t")
                    })
                line = file.readline()
    except Exception, e:
        print "Failed to parse hosts.txt: ", e
        sys.exit(1) 
          
    print 'DNS server running using file hosts.txt...'
  
    try:
        while 1:
            data, addr = udps.recvfrom(1024)   
            print '----------new request received at {0}----------'.format(time.time())   
            p=DNSQuery(data)
            print 'Type: ' + str(p.request.QTYPE_AS_STRING)
            ip = resolve_ip(p.request.QNAME)      
            udps.sendto(p.get_response(ip), addr)      
            print 'Request: %s maps to %s' % (p.request.QNAME, ip)
    except KeyboardInterrupt:
        print '\nBye!'
        udps.close()
    
    sys.exit(1)

