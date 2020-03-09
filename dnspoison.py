#DNS Poisoner (on path attack) using Scapy Framework. Python 3.

import argparse
import socket
from scapy.all import *

hostnames = None

def sniffLive(interfaceName, bpf):
    print('Sniffing live with bpf:{} in interface:{}\n'.format(bpf, interfaceName))
    sniff(prn=processPacket, filter=bpf, iface=interfaceName, store=0)
    return 0 

# Returns True if is targettable DNS request
def isRelevant(pkt):
    retval = False
    #test if packet is DNS request
    if not hostnames == None:
        pass    #tmp
        #test if packet hostname matches a specified hostname
    return retval

def processPacket(pkt):
    print(pkt.summary())
    if(isRelevant(pkt)):
        pass #tmp
        #identify redirect destination (current machine or other specified ip)
        #identify other fields necessary to forge packet
        #forge response packet
        #send forged packet
    else:
        return
    return

#loads hostname ip pairs from hostname file into dict
def loadHostnamesFile(hostnamesFile):
    if not os.path.exists(parsed.f):
        print('ERROR: Specified hostname file not found')
        exit(1)

    global hostnames
    hostnames = {}

    pattern = r'''(\S+)\s+(\S+)'''

    with open(hostnamesFile, 'r') as input:
        for line in input:
            m = re.find(pattern, line)

            #get these two from the line using regex
            currentHostname = 'tmp'
            currentIP = '192.168.1.1' #also tmp

            #check if hostname already loaded, if not, add to dict.
            if currentHostname in hostnames:
                print('ERROR: only one line per hostname')
                exit(1)
            else:
                hostnames[currentHostname] = currentIP
    return True

def main():
    print('Starting dnspoison.py')
    
    #parse args
    # dnspoison.py [-i interface] [-f hostnames] [-e expression]
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', nargs='?', \
            choices=[x[1] for x in socket.if_nameindex()], metavar='interfaceName', \
            help='specify interface to sniff packets on. Automatically picks if none specified.')
    
    #implement an array of options
    parser.add_argument('-f', metavar='hostnames.txt', \
      help='specify hostname ip pairs to hijack. 1 pair per line, separated by whitepace')

    parser.add_argument('-e', metavar='BPF', help='specify BPF expression')
    
    parsed = parser.parse_args()

    print(parsed)
  
    if parsed.i == None:
        interface = socket.if_nameindex()[0][1]
    else:
        interface = parsed.i
    
    if not parsed.f == None:
        loadHostnamesFile(parsed.f)

    sniffLive(interface, parsed.e)

    return

if __name__ == "__main__":
   main()





