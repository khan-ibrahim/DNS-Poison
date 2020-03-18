# DNS-Poison

[![Python 3.7.6](https://img.shields.io/badge/python-3.7.6-blue.svg)](https://www.python.org/downloads/release/python-376/)

Performs on-path DNS poisoning. Sniffs on specified interface with optional filter expression for DNS requests. 
Fabricates DNS response with fake different IP address, and sends it to the original requestor, arriving before DNS response from (far away) legitimate server.


## Usage

```
dnspoison.py [-h] [-i [interfaceName]] [-f hostnames.txt] [-e BPF]

optional arguments:
  -h, --help          show this help message and exit
  -i [interfaceName]  specify interface to sniff packets on. Automatically
                      picks if none specified.
  -f hostnames.txt    specify ip hostname pairs to hijack. 1 pair per
                      hostname, separated by whitepace
  -e BPF              specify BPF expression
```
