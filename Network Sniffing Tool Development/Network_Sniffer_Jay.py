import socket
import os
import logging
import datetime

LOG_FILE = "packet_sniffer.log"
BUFFER_SIZE = 65565

def configure_logger():
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def get_user_input():
    host = input("Enter the HOST (e.g., 192.168.1.1): ").strip()
    return host

def create_sniffer_socket(host):
    try:
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
            sniffer.bind((host, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            socket_protocol = socket.IPPROTO_ICMP
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
            sniffer.bind((host, 0))
        return sniffer
    except socket.error as e:
        logging.error(f"Error creating socket: {e}")
        raise

def receive_packets(sniffer):
    try:
        while True:
            raw_data, addr = sniffer.recvfrom(BUFFER_SIZE)
            packet_data = raw_data.decode('utf-8', errors='ignore')
            
            print(f"\n[+] {datetime.datetime.now()} - Packet from {addr[0]}:{addr[1]}")
            print(f"Packet Data:\n{packet_data}")
            
            logging.info(f"Packet Data from {addr[0]}:{addr[1]}:\n{packet_data}")

    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except KeyboardInterrupt:
        logging.info("User interrupted the program.")
    finally:
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

def main():
    configure_logger()
    logging.info("Packet sniffer started.")

    try:
        host = get_user_input()
        with create_sniffer_socket(host) as sniffer:
            receive_packets(sniffer)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
