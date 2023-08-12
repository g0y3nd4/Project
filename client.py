import socket
import getpass

def main():
    host = "127.0.0.1"
    port = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

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
