# client.py (Runs on the Controller PC)
import socket


def send_command(host, port, command):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            print(f"Attempting to connect to {host}:{port}...")
            s.connect((host, port))
            print("Connection successful. Sending command...")
            
            s.sendall(command.encode('utf-8'))
            
            # Wait for the server's response
            data = s.recv(1024)
            print(f"\n--- Server Response ---")
            print(data.decode('utf-8'))
            print("-----------------------")
            
        except ConnectionRefusedError:
            print(f"❌ Connection failed. Ensure the server script ({host}:{port}) is running.")
        except Exception as e:
            print(f"❌ An error occurred: {e}")

if __name__ == '__main__':
    send_command('192.168.137.1' , 65432, input("Command to execute : "))