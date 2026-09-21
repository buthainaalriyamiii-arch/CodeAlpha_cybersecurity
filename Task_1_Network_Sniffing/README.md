# Basic Network Sniffer

## Project Overview

This project is a basic network sniffer developed using Python's built-in `socket` library.

The purpose of the project is to capture network packets and analyze basic information from them, including source and destination IP addresses, protocols, ports, header lengths, and payload data.

## Objectives

* Capture network traffic packets.
* Understand the basic structure of network packets.
* Identify common network protocols.
* Extract source and destination IP addresses.
* Extract TCP and UDP port numbers.
* Calculate IP, TCP, and UDP header lengths.
* Extract and display packet payloads.
* Understand how data flows across a network.

## Technologies Used

* Python 3
* Python `socket`
* Python `struct`
* Windows
* Visual Studio Code

## How It Works

The program creates a raw IPv4 socket and listens for network traffic on the local network interface.

For each captured packet, the program extracts information from the IPv4 header:

* Source IP address
* Destination IP address
* Protocol number
* IP header length

The program then identifies the transport protocol.

### TCP

For TCP packets, the program extracts:

* Source port
* Destination port
* TCP header length
* Payload

### UDP

For UDP packets, the program extracts:

* Source port
* Destination port
* UDP header length
* Payload

### ICMP and IGMP

The program identifies ICMP and IGMP packets and displays their protocol names.

## Packet Analysis

During testing, the sniffer captured different types of network traffic.

### TCP Traffic

Example:

```text
Source IP: 192.168.1.116
Destination Port: 443
Protocol: TCP
TCP Header Length: 20
Payload length: 24
```

Port 443 is commonly used for HTTPS/TLS traffic. The captured payload appeared as binary/encrypted data rather than readable text.

### SSDP Traffic

The sniffer also captured UDP traffic using port 1900.

Example:

```text
Source Port: 58933
Destination Port: 1900
Protocol: UDP
UDP Header Length: 8
```

The payload contained:

```text
NOTIFY * HTTP/1.1
NTS: ssdp:alive
```

This indicates SSDP/UPnP discovery traffic.

### mDNS Traffic

The sniffer captured UDP traffic using port 5353.

Example:

```text
Source Port: 5353
Destination Port: 5353
Protocol: UDP
Destination IP: 224.0.0.251
```

This is multicast DNS (mDNS) traffic.

## Example Output

```text
[14:59:05] Packet #988
Packet length: 349
Source IP: 192.168.1.115
Destination IP: 239.255.255.250
Protocol: UDP
IP Header Length: 20
Source Port: 58933
Destination Port: 1900
UDP Header Length: 8
Payload length: 321
```

## Limitations

This project is a basic educational network sniffer and has several limitations:

* It focuses on IPv4 traffic.
* It does not decrypt HTTPS/TLS traffic.
* TCP streams are not reassembled into complete application messages.
* Payloads are displayed per packet rather than as complete communication sessions.
* The program does not provide advanced packet filtering or deep protocol analysis.
* Raw socket packet capture on Windows requires administrator privileges.

## What I Learned

Through this project, I learned how network packets are structured and how information can be extracted from raw packet data.

I practiced working with:

* Raw sockets
* IPv4 headers
* TCP and UDP headers
* IP addresses
* Port numbers
* Protocol identification
* Payload extraction
* Network traffic analysis

The project also helped me understand the difference between packet-level data and application-level communication.

## Conclusion

The Basic Network Sniffer successfully captures and analyzes network packets using Python sockets.

The project demonstrates how basic packet information can be extracted from raw network traffic and provides a foundation for further learning in network security, traffic analysis, and cybersecurity.
