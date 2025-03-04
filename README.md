# DNS Query Resolver

## Overview
This script is a simple DNS query resolver implemented in Python. It constructs and sends a DNS query to a specified DNS server (default: Google Public DNS 8.8.8.8), then parses and displays the response. The script supports parsing various DNS record types such as A, NS, CNAME, PTR, and MX.

## Features
- Constructs DNS queries for a given hostname
- Sends queries to a DNS server using UDP
- Parses DNS responses including Questions, Answers, Authority, and Additional sections
- Supports multiple record types: A, NS, CNAME, PTR, MX
- Implements domain name compression handling in DNS responses

## Requirements
- Python 3.x
- Internet connection (unless querying a local DNS server)

## Usage
Run the script with a hostname as an argument:
```sh
python3 dns_resolver.py example.com
```
Or, without an argument, it will prompt for user input:
```sh
python3 dns_resolver.py
Enter a hostname to look up: example.com
```

## Output Example
```sh
;; Got answer:
;; ->>HEADER<<- opcode: 0, status: 0, id: 12345
;; QUESTIONS: 1, ANSWERS: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;; example.com	IN	A

;; ANSWER SECTION:
example.com	3600	IN	A	93.184.216.34
example.com	3600	IN	A	93.184.216.35
```

## How It Works
1. **Builds a DNS Query**:
   - Constructs a raw DNS packet including the Header and Question sections.
   - Uses Type A (IPv4 address) and Class IN (Internet).

2. **Sends Query via UDP**:
   - Uses a socket to send the query to a DNS server (default: 8.8.8.8, port 53).
   - Waits for a response within a timeout (5 seconds).

3. **Parses the Response**:
   - Extracts and decodes sections: Questions, Answers, Authority, and Additional.
   - Handles compressed domain names in DNS responses.

4. **Displays the Result**:
   - Prints the resolved IP address or other record types.

## Customization
- **Change the DNS Server**:
  Modify the `dns_server` variable in `main()` to query a different server:
  ```python
  dns_server = ("1.1.1.1", 53)  # Cloudflare DNS
  ```

## Notes
- Uses the UDP protocol for efficiency (standard for DNS queries).
- Does not support TCP-based DNS queries (for large responses).
- Can be extended to support additional record types (e.g., AAAA, TXT).

## License
This script is provided under the MIT License. Feel free to modify and distribute it.

