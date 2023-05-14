import socket
import struct

def sniff(interface):
    # Create a raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

    # Bind the socket to the interface
    s.bind((interface, 0))

    # Start sniffing packets
    while True:
        # Receive a packet
        packet = s.recvfrom(65535)

        # Get the packet data
        data = packet[0]

        # Get the packet headers
        (packet_type, packet_length, source_address, destination_address, protocol) = struct.unpack("!BBHII", data[:20])

        # Print the packet information
        print("Packet type:", packet_type)
        print("Packet length:", packet_length)
        print("Source address:", source_address)
        print("Destination address:", destination_address)
        print("Protocol:", protocol)


if __name__ == "__main__":
    # Get the interface to sniff on
    interface = input("Enter the interface to sniff on: ")

    # Start sniffing
    sniff(interface)
