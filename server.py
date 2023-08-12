import socket
import bcrypt

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

def main():
    host = "127.0.0.1"
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)

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
    main()
