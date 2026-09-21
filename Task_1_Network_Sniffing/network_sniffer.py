import socket
import struct
from datetime import datetime

HOST = socket.gethostbyname(socket.gethostname())

sniffer = socket.socket(
    socket.AF_INET,
    socket.SOCK_RAW,
    socket.IPPROTO_IP
)

sniffer.bind((HOST, 0))

sniffer.setsockopt(
    socket.IPPROTO_IP,
    socket.IP_HDRINCL,
    1
)

sniffer.ioctl(
    socket.SIO_RCVALL,
    socket.RCVALL_ONSs
)

print(f"Sniffer started on {HOST}")
print("Waiting for packets...")
print("Press Ctrl+C to stop.\n")

packet_number = 0

try:
    while True:

        packet, address = sniffer.recvfrom(65565)

        packet_number += 1

        timestamp = datetime.now().strftime("%H:%M:%S")

        print("=" * 50)
        print(f"[{timestamp}] Packet #{packet_number}")
        print("Packet length:", len(packet))

        source_ip = socket.inet_ntoa(packet[12:16])
        destination_ip = socket.inet_ntoa(packet[16:20])
        protocol = packet[9]

        print("Source IP:", source_ip)
        print("Destination IP:", destination_ip)
        print("Protocol:", protocol)

        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        elif protocol == 2:
            protocol_name = "IGMP"
        else:
            protocol_name = "Other"

        print("Protocol:", protocol_name)

        ip_header_length = (packet[0] & 0x0F) * 4

        print("IP Header Length:", ip_header_length)

        transport_header = packet[ip_header_length:]

        if protocol == 6:

            source_port, destination_port = struct.unpack(
                "!HH",
                transport_header[:4]
            )

            print("Source Port:", source_port)
            print("Destination Port:", destination_port)
            print("Transport Protocol:", protocol_name)

            tcp_header_length = (
                ((transport_header[12] >> 4) & 0x0F) * 4
            )

            print("TCP Header Length:", tcp_header_length)

            payload = packet[
                ip_header_length + tcp_header_length:
            ]

        elif protocol == 17:

            udp_header_length = 8

            source_port, destination_port = struct.unpack(
                "!HH",
                transport_header[:4]
            )

            print("Source Port:", source_port)
            print("Destination Port:", destination_port)
            print("Transport Protocol:", protocol_name)

            print("UDP Header Length:", udp_header_length)

            payload = packet[
                ip_header_length + udp_header_length:
            ]

        elif protocol == 1:

            print("Transport Protocol:", protocol_name)

            payload = transport_header

        else:

            print("Transport Protocol:", protocol_name)

            payload = transport_header

        print("Payload length:", len(payload))
        print("Payload:", payload[:100])

except KeyboardInterrupt:

    print("\nStopping sniffer...")

finally:

    sniffer.ioctl(
        socket.SIO_RCVALL,
        socket.RCVALL_OFF
    )

    sniffer.close()

    print("Sniffer stopped.")