import socket
import getpass
import re
from scapy.all import sniff, Ether

#/bin/python3 /home/user/test/client.py
#---------------Analyisis packet & ex Ip and Port-------
port=''
stop_sniffing = False
def packet_handler(packet):
    global ip_address
    global port
    global stop_sniffing

    if packet.haslayer(Ether) and packet[Ether].dst == "ff:ff:ff:ff:ff:ff":
        print(f"Received Ethernet Frame: {packet.summary()}")
        if hasattr(packet.payload, 'load'):
            payload_data = packet.payload.load.decode('utf-8', errors='ignore')
            print("Payload Data:", payload_data)

            # regular expression
            pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(\d{1,5}),'
            if re.match(pattern, payload_data):
                ip_address, port, null = payload_data.split(',')
                print(f"Match found & The IP: {ip_address} & Port:{port}")
                stop_sniffing = True
            else:
                print("No match.")

#-----------------------------------------------------------------------------------------
def discovery_type():
    global ip_address
    global port
    print("You can select auto or manual discovery. For Auto select:1. Manual:2.")
    choose = input("Enter your choose:")
    if choose == "1":
        print("Trying to auto Server discovery")
        #----------------------Capture broadcast frame-------------------------------------------
        sniff(iface='ens33', prn=packet_handler, stop_filter=lambda pkt: stop_sniffing, count=1000)
    elif choose == "2":
        ip_address = input("Enter the server ip address:")
        port = input("Enter the port number:")
        return port
    else:
        print("You choose a wrong options. Try again")


#------------------------------------------------------------------------------------------
def main():
    discovery_type()
#----------------Create clint---------------------------------------------
    port_int = int((port))
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ip_address, port_int))

#---------------Authentication------------------------------------
    authenticated = False
    while not authenticated:
        print(client_socket.recv(1024).decode())
        password =getpass.getpass("Enter your password: ")
        client_socket.send(password.encode())

        auth_response = client_socket.recv(1024).decode()
        if auth_response == "Authenticated":
            authenticated = True
            print("Authentication Successful")
        else:
            print("Authentication Failed. Please try again.")
#--------------------Communicate with server--------------------------
    while True:
        message = input("Enter Message ('exit' to quit): ")
        client_socket.send(message.encode())

        if message.lower() == "exit":
            break

        reply = client_socket.recv(1024).decode()
        print("Server Reply:", reply)

    client_socket.close()

if __name__ == "__main__":
    main()
