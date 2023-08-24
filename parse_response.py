from build_query import DNSHeader, DNSQuestion, build_query
from dataclasses import dataclass
from typing import List

@dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes

@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]

import struct
def parse_header(reader):
    items = struct.unpack("!HHHHHH",reader.read(12))
    return DNSHeader(*items)

def decode_simple_name(reader):
    parts = []
    while(length := reader.read(1)[0]) !=0:
        if(length & 0b1100_0000):
            parts.append(decode_compressed_name(length,reader))
            break
        else:
            parts.append(reader.read(length))
    return b'.'.join(parts)

def decode_compressed_name(length,reader):
    name_pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    name_pointer = struct.unpack("!H",name_pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(name_pointer)
    result = decode_simple_name(reader)
    reader.seek(current_pos)
    return result

def parse_question(reader):
    name = decode_simple_name(reader)
    type_, class_ = struct.unpack("!HH",reader.read(4))
    return DNSQuestion(name,type_,class_)

def parse_record(reader):
    name = decode_simple_name(reader)
    type_,class_,ttl,data_length = struct.unpack("!HHIH",reader.read(10))
    TYPE_A = 1
    TYPE_NS = 2
    if(type_ == TYPE_A):
        data = ".".join([str(x) for x in reader.read(data_length)])
    elif type_ == TYPE_NS:
        data = decode_simple_name(reader)
    else:
        data = reader.read(data_length)
    return DNSRecord(name,type_,class_,ttl,data)

from io import BytesIO
def parse_dns_packet(data):
    reader = BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]
    return DNSPacket(header,questions,answers,authorities,additionals)
