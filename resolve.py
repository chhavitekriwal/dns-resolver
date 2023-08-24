from build_query import build_query
from parse_response import parse_dns_packet

root_server = "192.36.148.17"                   # IP address of i.root-servers.net.


import socket
def send_query(address,domain_name,record_type):
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    query= build_query(domain_name,record_type)
    sock.sendto(query,(address,53))
    response,_ = sock.recvfrom(1024)
    return parse_dns_packet(response)
    

TYPE_A = 1
TYPE_NS = 2

def get_answer(packet):
    for record in packet.answers:
        if record.type_ == TYPE_A:
            return record.data
def get_nameserver_ip(packet):
    for record in packet.additionals:
        if record.type_ == TYPE_A:
            return record.data
        
def get_nameserver(packet):
    for record in packet.authorities:
        return record.data.decode()
    
def resolve(domain_name, record_type):
    server = "192.36.148.17"
    while True:
        print(f"Querying {server} for {domain_name}")
        packet = send_query(server,domain_name,record_type)
        if ip := get_answer(packet):
            return ip
        elif ns_ip := get_nameserver_ip(packet):
            server = ns_ip
        elif ns := get_nameserver(packet):
            server = resolve(ns,1)
        else:
            raise Exception("something went wrong")
        
print(resolve("twitter.com",1))