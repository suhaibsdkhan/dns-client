#!/usr/bin/env python3

import socket
import random
import sys
import struct

def build_dns_query(hostname, query_id=None):
    """
    Builds a DNS query packet for the given hostname (Type A, Class IN).
    Returns the raw bytes of the DNS query.
    """
    if query_id is None:
        query_id = random.randint(0, 65535)
    
    # HEADER Section (12 bytes)
    #   ID (16 bits)
    #   Flags (16 bits) -> 0x0100 = standard query, recursion desired
    #   QDCOUNT (16 bits) -> number of questions, here 1
    #   ANCOUNT (16 bits) -> number of answers, here 0 in query
    #   NSCOUNT (16 bits) -> number of authority records, 0
    #   ARCOUNT (16 bits) -> number of additional records, 0
    flags = 0x0100
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    
    header = struct.pack(
        "!HHHHHH",
        query_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount
    )
    
    # QUESTION Section
    #   QNAME: a sequence of labels, each label is:
    #       length byte + label bytes
    #   Terminated by a '0' length byte.
    qname = b""
    for label in hostname.split("."):
        qname += struct.pack("B", len(label)) + label.encode()
    qname += b"\x00"
    
    #   QTYPE (16 bits) -> 1 = A
    #   QCLASS (16 bits) -> 1 = IN
    qtype = 1
    qclass = 1
    question = struct.pack("!HH", qtype, qclass)
    
    return header + qname + question

def parse_dns_response(response):
    """
    Parses the DNS response, extracting the answer records and returning them.
    Returns a dict that includes the question and the answers with IPs.
    """
    # First 12 bytes are the header:
    #   ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    # Each are 2 bytes (16 bits).
    (resp_id,
     flags,
     qdcount,
     ancount,
     nscount,
     arcount) = struct.unpack("!HHHHHH", response[:12])
    
    offset = 12

    # Parse Question Section
    questions = []
    for _ in range(qdcount):
        qname, offset = read_qname(response, offset)
        qtype, qclass = struct.unpack("!HH", response[offset:offset+4])
        offset += 4
        questions.append((qname, qtype, qclass))
    
    # Parse Answer Section
    answers = []
    for _ in range(ancount):
        name, offset = read_qname(response, offset)
        rtype, rclass, rttl, rdlength = struct.unpack("!HHIH", response[offset:offset+10])
        offset += 10
        
        if rtype == 1 and rdlength == 4:  # A record
            ip_bytes = response[offset:offset+4]
            ip_addr = ".".join(str(b) for b in ip_bytes)
            offset += 4
            answers.append((name, rtype, rclass, rttl, ip_addr))
        else:
            # Skip over resource data we don’t parse
            offset += rdlength
    
    return {
        "response_id": resp_id,
        "flags": flags,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "questions": questions,
        "answers": answers
    }

def read_qname(data, offset):
    """
    Reads a compressed (or uncompressed) domain name starting at 'offset' in the DNS message.
    Returns (qname_string, new_offset).

    This function handles DNS name compression pointers (0xC0xx).
    """
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length_or_pointer = data[offset]

        # Check for a pointer: 0xC0 == 11000000 in binary
        if (length_or_pointer & 0xC0) == 0xC0:
            # The next byte + lower 6 bits of current byte forms the pointer offset
            pointer = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            offset += 2
            # Decode the name from the pointer location
            pointed_name, _ = read_qname(data, pointer)
            labels.append(pointed_name)
            jumped = True
            break
        else:
            offset += 1
            if length_or_pointer == 0:
                break
            label = data[offset:offset+length_or_pointer].decode()
            offset += length_or_pointer
            labels.append(label)

    # If we used a pointer, we stop reading further labels in this chain
    if not jumped:
        name = ".".join(labels)
        return name, offset
    else:
        # Combine labels read so far
        name = ".".join(labels)
        return name, offset

def main():
    # Get hostname (either from argv or prompt user)
    if len(sys.argv) < 2:
        hostname = input("Enter a hostname to look up: ").strip()
    else:
        hostname = sys.argv[1]
    
    # Build DNS query
    query_packet = build_dns_query(hostname)
    
    # Choose a DNS server to query (Google Public DNS here)
    dns_server = ("8.8.8.8", 53)

    # Send query via UDP
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)  # 5 seconds timeout
        s.sendto(query_packet, dns_server)
        try:
            response, _ = s.recvfrom(512)  # typical 512-byte max for DNS over UDP
        except socket.timeout:
            print("Request timed out.")
            sys.exit(1)
    
    # Parse response
    result = parse_dns_response(response)
    
    # Display results
    print(f"\n;; Got answer:")
    print(f";; ->>HEADER<<- opcode: {(result['flags'] >> 11) & 0xF}, "
          f"status: {result['flags'] & 0xF}, id: {result['response_id']}")
    print(f";; QUESTIONS: {result['qdcount']}, ANSWERS: {result['ancount']}, "
          f"AUTHORITY: {result['nscount']}, ADDITIONAL: {result['arcount']}\n")

    for (qname, qtype, qclass) in result["questions"]:
        print(";; QUESTION SECTION:")
        print(f";; {qname}\tIN\tA")

    if result["answers"]:
        print("\n;; ANSWER SECTION:")
        for (name, rtype, rclass, ttl, ip_addr) in result["answers"]:
            print(f"{name}\t{ttl}\tIN\tA\t{ip_addr}")
    else:
        print("No A record answers found.")

if __name__ == "__main__":
    main()