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
    header = DNSHeader(header_id,0,1)

    question = DNSQuestion(encode_domain_name(domain_name),record_type,CLASS_IN)
    query = header_to_bytes(header) + question_to_bytes(question)
    return query
