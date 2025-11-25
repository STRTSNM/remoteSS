import socket
import sys


def send_command(host, port, command):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
            s.sendall(command.encode("utf-8"))

            data = s.recv(4096)

            print(f"\n--- Server Response ---")
            print(data.decode("utf-8"))
            print("-----------------------")

        except ConnectionRefusedError:
            print(f"Error: Could not connect to {host}:{port}")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    HOST = "192.168.137.1"
    PORT = 65432

    if len(sys.argv) > 1:
        cmd = " ".join(sys.argv[1:])
    else:
        cmd = input("Command to execute : ")

    send_command(HOST, PORT, cmd)
