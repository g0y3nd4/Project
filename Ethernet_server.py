from scapy.all import Ether, sendp
import socket
import bcrypt
import random
import time
import threading

# Server configuration
host = ''
port = 0
# List of connected clients
clients = []
auth_clients=[]


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
#-----------------------------Authentication------------------------------------------------
def authenticate(client_socket):
    with open("hashed_password.txt", "rb") as file:
        stored_hashed_password = file.read() 
    client_socket.send("You want to connect with JGEC server".encode())
    password_encode = client_socket.recv(1024).decode().strip()
   
    if bcrypt.checkpw(password_encode.encode(), stored_hashed_password):
        client_socket.send("Authenticated".encode())
        print(f"Client authetication successfull: {client_socket.getpeername()}")
        auth_clients.append(client_socket)       
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()
        return True
            
    else:
        client_socket.send("Authentication Failed".encode())
        print("Authentication Failed")
        client_socket.close()
        clients.remove(client_socket)
        return False
#------------------------------Broadcast-------------------------------------------------
host = get_network_ip()      #IP from function
port = int(random.randint(12345, 12345))  #Generate Random port
addr=(host, port)

def broadcast():
    while True:
        payload_data = f"{host},{port},"     #Make frame payload
        ethernet_frame = Ether(src='00:0c:29:1a:1d:3a', dst='ff:ff:ff:ff:ff:ff') / payload_data

        sendp(ethernet_frame, iface='Ethernet', verbose=False, count=2)   #broadcast the payload
        time.sleep(3)

#------------------------Handle Client-----------------------------------------------
def handle_client(client_socket):
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            message = data.decode('utf-8')
            print(f"Received from {client_socket.getpeername()}: {message}")
            # Echo back the received message to the client
            client_socket.send(f"Data Sucessfully received by Server".encode('utf-8'))
    finally:
        client_socket.close()
        auth_clients.remove(client_socket)
        print(f"Connection closed with {client_socket.getpeername()}")


#-------------------------------Main Function------------------------------------------
def main():

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(addr)
    server_socket.listen()

    print(f"Server is listening on{addr} ")


    # Accept and handle multiple client connections
    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            clients.append(client_socket)
            print(f"Connection From {client_addr}")
            authentication = threading.Thread(target=authenticate, args=(client_socket,))
            authentication.start()
        
    except KeyboardInterrupt:
        print("Server shutting down...")
        for client_socket in auth_clients:
            client_socket.close()
        server_socket.close()
    


if __name__ == "__main__":
    background_thread = threading.Thread(target=broadcast)
    background_thread.daemon = True
    background_thread.start()
    main()
