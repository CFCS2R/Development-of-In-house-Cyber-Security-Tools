import os
import getpass
import socket
import shutil
import scapy.all as sc

# Define color codes for terminal output
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[32m"  # Changed color to green
COLOR_RESET = "\033[0m"
COLOR_MAGENTA = "\033[95m"  # Changed color to magenta
COLOR_YELLOW = "\033[33m"
COLOR_CYAN = "\033[36m"

counter = 0  # Initialize packet counter

# Function to retrieve protocol name from protocol number
def proto_name_by_num(proto_num):
    """
    Function to get the protocol name from the protocol number
    """
    for name, num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Not Found"

# Callback function to display captured packets
def display_packets(pkt):
    """
    Callback function to display captured packets
    """
    global counter
    counter += 1
    try:
        protocol = proto_name_by_num(pkt.proto)
    except AttributeError:
        protocol = "error"
   
    try:
        payload = pkt.load
    except:
        # If payload cannot be loaded, print packet details without payload
        print(f"{str(counter).ljust(10)}{protocol.ljust(10)}{pkt['IP'].src.ljust(20)}{pkt['IP'].dst.ljust(20)}{str(pkt.len).ljust(10)}")
    else:
        # Print packet details with payload (if available)
        print(f"{str(counter).ljust(10)}{protocol.ljust(10)}{pkt['IP'].src.ljust(20)}{pkt['IP'].dst.ljust(20)}{str(pkt.len).ljust(10)}{COLOR_CYAN}{''.join([chr(byte) if 31 < byte < 127 else '·' for byte in payload[:shutil.get_terminal_size().columns - 70]]).ljust(100)}{COLOR_RESET}")

# Function to capture packets on the specified interface
def capture_packets(interface):
    """
    Function to capture packets on the specified interface
    """
    print(COLOR_MAGENTA)
    print("Press Ctrl+C to stop capturing.")
    print(COLOR_RESET)
    print(COLOR_YELLOW)
    print("Sr. No.".ljust(10), "Protocol".ljust(10), "Source".ljust(20), "Destination".ljust(20), "Length".ljust(10), "Payload".ljust(100), sep='')
    print(COLOR_RESET)
    
    # Capture packets using Scapy
    pkt_capture = sc.sniff(iface=interface, prn=display_packets)

    while True:
        print(COLOR_MAGENTA)
        print("\nTo inspect a packet in detail, enter the index of that packet. To quit, enter 0: ", end='')
        print(COLOR_RESET, end='')
        ch2 = int(input())
        
        if ch2 == 0: 
            exit(0)
        else:
            try:
                print(COLOR_GREEN)
                print((f" Detailed view of packet #{ch2} ").center(shutil.get_terminal_size().columns, "="))
                print(COLOR_RESET)
                pkt_capture[ch2 - 1].show()
                try:
                    payload = pkt_capture[ch2 - 1].load
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
                go_back = input()
                
                if go_back.upper() == "R":
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

if __name__ == "__main__":
    # Display available network interfaces
    print(COLOR_GREEN)
    print((" Network Interfaces Present ").center(100, "="))
    print(COLOR_RESET)
    print(sc.conf.ifaces)

    # Prompt user to select interface for packet capture
    print(COLOR_MAGENTA)
    print("Enter the index of the interface to capture: ", end='')
    print(COLOR_RESET, end='')
    
    ch = int(input())
    
    if ch == 0:
        exit(0)
    
    try:
        interface_name = sc.dev_from_index(ch)
        print(f"Capturing traffic from {interface_name}...")
    except:
        print("Interface does not exist. Try again or choose 0 to quit.")
        exit(0)
    
    
    
    # Start capturing packets on the selected interface
    capture_packets(interface_name)
