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
    #   ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    flags = 0x0100  # standard query with recursion desired
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", query_id, flags, qdcount, ancount, nscount, arcount)
    
    # QUESTION Section: construct QNAME
    qname = b""
    for label in hostname.split("."):
        qname += struct.pack("B", len(label)) + label.encode()
    qname += b"\x00"  # Terminate with zero length
    
    # QTYPE and QCLASS (both 2 bytes)
    qtype = 1  # A record
    qclass = 1  # IN (Internet)
    question = struct.pack("!HH", qtype, qclass)
    
    return header + qname + question

def read_qname(data, offset):
    """
    Reads a compressed (or uncompressed) domain name starting at 'offset' in the DNS message.
    Returns (qname_string, new_offset).
    """
    labels = []
    jumped = False

    while True:
        length_or_pointer = data[offset]
        # Check for pointer (two most significant bits set)
        if (length_or_pointer & 0xC0) == 0xC0:
            pointer = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            offset += 2
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
    name = ".".join(labels)
    if not jumped:
        return name, offset
    else:
        return name, offset

def parse_rr(data, offset):
    """
    Parses a resource record starting at offset in the DNS message.
    Returns a tuple (rr_dict, new_offset) where rr_dict contains:
      - name, rtype, rclass, ttl, rdlength, and a parsed rdata.
    """
    name, offset = read_qname(data, offset)
    rtype, rclass, rttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
    offset += 10
    rdata_start = offset
    rdata_end = offset + rdlength
    rdata = data[offset:rdata_end]
    offset = rdata_end
    
    # Attempt to parse rdata based on type
    if rtype == 1 and rdlength == 4:
        # A record: convert 4 bytes to an IP address
        parsed_rdata = ".".join(str(b) for b in rdata)
    elif rtype in [2, 5, 12]:
        # NS, CNAME, PTR records: rdata is a domain name
        parsed_rdata, _ = read_qname(data, rdata_start)
    elif rtype == 15 and rdlength >= 3:
        # MX record: first 2 bytes = preference, remainder is exchange domain
        pref = struct.unpack("!H", rdata[:2])[0]
        exchange, _ = read_qname(data, rdata_start+2)
        parsed_rdata = f"{pref} {exchange}"
    else:
        # Fallback: display raw rdata as hex
        parsed_rdata = rdata.hex()
    
    rr = {
        "name": name,
        "rtype": rtype,
        "rclass": rclass,
        "ttl": rttl,
        "rdlength": rdlength,
        "rdata": parsed_rdata
    }
    return rr, offset

def parse_dns_response(response):
    """
    Parses the DNS response, extracting the Question, Answer, Authority, and Additional sections.
    Returns a dictionary containing all parsed sections.
    """
    (resp_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack("!HHHHHH", response[:12])
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
        rr, offset = parse_rr(response, offset)
        answers.append(rr)
    
    # Parse Authority Section
    authorities = []
    for _ in range(nscount):
        rr, offset = parse_rr(response, offset)
        authorities.append(rr)
    
    # Parse Additional Section
    additionals = []
    for _ in range(arcount):
        rr, offset = parse_rr(response, offset)
        additionals.append(rr)
    
    return {
        "response_id": resp_id,
        "flags": flags,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals
    }

def main():
    # Obtain hostname from command-line arguments or prompt
    if len(sys.argv) < 2:
        hostname = input("Enter a hostname to look up: ").strip()
    else:
        hostname = sys.argv[1]
    
    # Build DNS query packet
    query_packet = build_dns_query(hostname)
    
    # Choose a DNS server (default is Google Public DNS; change if a local DNS is preferred)
    dns_server = ("8.8.8.8", 53)
    # For a local DNS server, you might use: dns_server = ("127.0.0.1", 53)

    # Send query via UDP
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)  # 5-second timeout
        s.sendto(query_packet, dns_server)
        try:
            response, _ = s.recvfrom(512)  # Typical maximum DNS message size for UDP
        except socket.timeout:
            print("Request timed out.")
            sys.exit(1)
    
    # Parse the DNS response
    result = parse_dns_response(response)
    
    # Display header information
    print(f"\n;; Got answer:")
    print(f";; ->>HEADER<<- opcode: {(result['flags'] >> 11) & 0xF}, "
          f"status: {result['flags'] & 0xF}, id: {result['response_id']}")
    print(f";; QUESTIONS: {result['qdcount']}, ANSWERS: {result['ancount']}, "
          f"AUTHORITY: {result['nscount']}, ADDITIONAL: {result['arcount']}\n")

    # Display Question Section
    if result["questions"]:
        print(";; QUESTION SECTION:")
        for (qname, qtype, qclass) in result["questions"]:
            print(f";; {qname}\tIN\tA")
    else:
        print("No questions found.")
    
    # Helper mapping for common record types
    type_map = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX"}
    
    # Display Answer Section
    if result["answers"]:
        print("\n;; ANSWER SECTION:")
        for rr in result["answers"]:
            rtype_str = type_map.get(rr["rtype"], f"TYPE{rr['rtype']}")
            print(f"{rr['name']}\t{rr['ttl']}\tIN\t{rtype_str}\t{rr['rdata']}")
    else:
        print("\nNo answers found.")
    
    # Display Authority Section
    if result["authorities"]:
        print("\n;; AUTHORITY SECTION:")
        for rr in result["authorities"]:
            rtype_str = type_map.get(rr["rtype"], f"TYPE{rr['rtype']}")
            print(f"{rr['name']}\t{rr['ttl']}\tIN\t{rtype_str}\t{rr['rdata']}")
    
    # Display Additional Section
    if result["additionals"]:
        print("\n;; ADDITIONAL SECTION:")
        for rr in result["additionals"]:
            rtype_str = type_map.get(rr["rtype"], f"TYPE{rr['rtype']}")
            print(f"{rr['name']}\t{rr['ttl']}\tIN\t{rtype_str}\t{rr['rdata']}")
    
if __name__ == "__main__":
    main()
