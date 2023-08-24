from build_query import build_query
from parse_response import parse_dns_packet                


import socket
def send_query(address,domain_name,record_type):
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    query= build_query(domain_name,record_type)
    sock.sendto(query,(address,53))
    response,_ = sock.recvfrom(1024)
    return parse_dns_packet(response)
    

TYPE_A = 1

def get_answer(packet):                                             # get IP from Answer section of DNS response
    for record in packet.answers:
        if record.type_ == TYPE_A:
            return record.data
def get_nameserver_ip(packet):                                      # IP of authoritative nameservers
    for record in packet.additionals:
        if record.type_ == TYPE_A:
            return record.data
        
def get_nameserver(packet):                                         # if IP of authoritative nameserver not given in additional section
    for record in packet.authorities:
        return record.data.decode()
    
def resolve(domain_name, record_type):
    server = "192.36.148.17"                                        # IP address of i.root-servers.net.
    while True:
        print(f"Querying {server} for {domain_name}")
        packet = send_query(server,domain_name,record_type)
        if ip := get_answer(packet):                                # if answer section contains the A record, return
            return ip
        elif ns_ip := get_nameserver_ip(packet):                    # if additional section contains A record for NS, query the NS
            server = ns_ip
        elif ns := get_nameserver(packet):                          # if additional section doesn't contain A rec for NS, ask root-server
            server = resolve(ns,1)
        else:
            raise Exception("something went wrong")                 # TODO: Better error handling
        
print(resolve("twitter.com",TYPE_A))