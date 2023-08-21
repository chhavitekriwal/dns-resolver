from dataclasses import dataclass
import dataclasses
import struct

@dataclass
class DNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0

@dataclass
class DNSQuestion:
    name: bytes
    type_ : int
    class_ : int

def header_to_bytes(header):
    fields = dataclasses.astuple(header)
    return struct.pack("!HHHHHH", *fields)

def encode_domain_name(domain_name):
    encoded_domain_name = b""
    for word in domain_name.encode("ascii").split(b"."):
        encoded_domain_name += bytes([len(word)])+word
    encoded_domain_name+=b"\x00"
    return encoded_domain_name

def question_to_bytes(question):
    return question.name + struct.pack("!HH",question.type_,question.class_)

import random

TYPE_A = 1
CLASS_IN = 1

def build_query(domain_name,record_type):
    header_id = random.randint(0,65536)
    RECURSION_REQUIRED = 1<<8
    header = DNSHeader(header_id,RECURSION_REQUIRED,1)

    question = DNSQuestion(encode_domain_name(domain_name),record_type,CLASS_IN)
    query = header_to_bytes(header) + question_to_bytes(question)
    return query

import socket

query = build_query("google.com",1)

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

sock.sendto(query,("8.8.8.8",53))

response, _ = sock.recvfrom(1024)