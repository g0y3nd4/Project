from scapy.all import Ether, sendp
import socket
import bcrypt
import random
import sys
import os
import time
import threading

#----------------------Get IP------------------------------------------
def get_network_ip():
    try:
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to Google DNS server

        # Get the IP address from the connected socket
        ip_address = s.getsockname()[0]
    except Exception as e:
        print("Error:", e)
        ip_address = None
    finally:
        s.close()

    return ip_address #Return IP address
#----------------------Authentication----------------------------------
def authenticate(client_socket):
    with open("hashed_password.txt", "rb") as file:
        stored_hashed_password = file.read() 
    client_socket.send("You want to connect with JGEC server".encode())
    password_encode = client_socket.recv(1024).decode().strip()
   
    if bcrypt.checkpw(password_encode.encode(), stored_hashed_password):
        client_socket.send("Authenticated".encode())
        print("Client authetication successfull")
        return True
            
    else:
        client_socket.send("Authentication Failed".encode())
        print("Authentication Failed")
        return False
#----------------------------------------------------------------------
host = get_network_ip()      #IP from function
port = int(random.randint(1234, 1234))  #Generate Random port
def broadcast():
    while True:
        payload_data = f"{host},{port},"     #Make frame payload
        ethernet_frame = Ether(src='00:0c:29:1a:1d:3a', dst='ff:ff:ff:ff:ff:ff') / payload_data

        sendp(ethernet_frame, iface='eth0', count=2)   #broadcast the payload
        time.sleep(3)


def main():

#---------Create a server-------------------------------------------
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print("Server listening on", host, port)

    client_socket, client_address = server_socket.accept()
    print("Connection from:", client_address)

    if authenticate(client_socket):
        while True:
            message = client_socket.recv(1024).decode().strip()
            if message.lower() == "exit":
                break
            print("Received:", message)

            reply = input("Enter Reply: ")
            client_socket.send(reply.encode())

    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    background_thread = threading.Thread(target=broadcast)
    background_thread.daemon = True
    background_thread.start()
    main()
