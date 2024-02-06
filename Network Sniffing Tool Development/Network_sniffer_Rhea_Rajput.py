#!/bin/python
import os, socket,shutil
import scapy.all as sc

COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_RESET = "\033[0m"
COLOR_MAGENTA = "\033[35m"
COLOR_YELLOW = "\033[33m"
COLOR_CYAN = "\033[36m"

counter=0
def proto_name_by_num(proto_num): # function to get the protocol name from the protocol number
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Not Found"
print(COLOR_GREEN)
print((" Network Interfaces Present ").center(100, "="))
print(COLOR_RESET)
print(sc.conf.ifaces)

def display_packets(pkt):
    global counter
    counter+=1
    try:
        protocol=proto_name_by_num(pkt.proto)
    except AttributeError:
        protocol="error"
   
    try:
        payload=pkt.load
      
    except:
        print(f"{str(counter).ljust(10)}{protocol.ljust(10)}{pkt['IP'].src.ljust(20)}{pkt['IP'].dst.ljust(20)}{str(pkt.len).ljust(10)}")
    else:
        print(f"{str(counter).ljust(10)}{protocol.ljust(10)}{pkt['IP'].src.ljust(20)}{pkt['IP'].dst.ljust(20)}{str(pkt.len).ljust(10)}{COLOR_CYAN}{''.join([chr(byte) if 31 < byte < 127 else '·' for byte in payload[:shutil.get_terminal_size().columns - 70]]).ljust(100)}{COLOR_RESET}")
    
        
def capture_packets(interface):
    print(COLOR_MAGENTA)
    print("Press Ctrl+C to stop capturing.")
    print(COLOR_RESET)
    print(COLOR_YELLOW)
    print("Sr. No.".ljust(10), "Protocol".ljust(10), "Source".ljust(20), "Destination".ljust(20), "Length".ljust(10), "Payload".ljust(100), sep='')
    print(COLOR_RESET)
    pkt_capture = sc.sniff(iface=interface, prn=display_packets)
    while(True):
        print(COLOR_MAGENTA)
        print("\nTo inspect a packet in detail, enter the Index of that packet. To quit, enter 0: ",end='')
        print(COLOR_RESET, end='')
        ch2=int(input())
        if ch2==0: 
            exit(0)
        else:
            try:
                print(COLOR_GREEN)
                print((f" Detailed view of packet #{ch2} ").center(shutil.get_terminal_size().columns, "="))
                print(COLOR_RESET)
                pkt_capture[ch2-1].show()
                try:
                    payload=pkt_capture[ch2-1].load
                except AttributeError:
                    pass
                else:
                    print("Load decoded as ASCII:")
                    ascii_representation = ''.join([chr(byte) if 31 < byte < 127 else '·' for byte in payload])
                    print(COLOR_CYAN)
                    print(ascii_representation)
                    print(COLOR_RESET)
                print(COLOR_MAGENTA)
                print("To return to packets list, enter 'R': ", end='')
                print(COLOR_RESET, end='')
                go_back=input()
                if go_back.upper()=="R":
                    global counter
                    counter = 0
                    print(COLOR_YELLOW)
                    print("Sr. No.".ljust(10), "Protocol".ljust(10), "Source".ljust(20), "Destination".ljust(20), "Length".ljust(10), "Payload".ljust(100), sep='')
                    print(COLOR_RESET)
                    for i in pkt_capture:
                        display_packets(i)
                else:
                    exit(0)

            except IndexError:
                print("That packet does not exist!")
print(COLOR_MAGENTA)
print("Enter the index of the interface to capture: ", end='')
print(COLOR_RESET, end='')
ch=int(input())
if ch==0:
    exit(0)
try:
    print(f"Capturing traffic from {sc.dev_from_index(ch)}...")
except:
    print("Interface does not exist. Try again or choose 0 to quit.")
else:
    if os.geteuid()!=0:
        print("This script must be run as sudo.")
        exit(0)
    capture_packets(sc.dev_from_index(ch))

