import os
import socket
import subprocess
import time
from datetime import datetime

from PIL import ImageGrab

HOST = "0.0.0.0"
PORT = 65432
HOTSPOT_IP = "192.168.137.1"

SS_FOLDER = f"C:\\Users\\{os.getlogin()}\\Desktop\\testing"
if not os.path.exists(SS_FOLDER):
    os.makedirs(SS_FOLDER)

encd_cmd = "QQBkAGQALQBUAHkAcABlACAALQBBAHMAcwBlAG0AYgBsAHkATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AUgB1AG4AdABpAG0AZQAuAFcAaQBuAGQAbwB3AHMAUgB1AG4AdABpAG0AZQAKACQAYQBzAFQAYQBzAGsARwBlAG4AZQByAGkAYwAgAD0AIAAoAFsAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAFIAdQBuAHQAaQBtAGUAUwB5AHMAdABlAG0ARQB4AHQAZQBuAHMAaQBvAG4AcwBdAC4ARwBlAHQATQBlAHQAaABvAGQAcwAoACkAIAB8ACAAPwAgAHsAIAAkAF8ALgBOAGEAbQBlACAALQBlAHEAIAAnAEEAcwBUAGEAcwBrACcAIAAtAGEAbgBkACAAJABfAC4ARwBlAHQAUABhAHIAYQBtAGUAdABlAHIAcwAoACkALgBDAG8AdQBuAHQAIAAtAGUAcQAgADEAIAAtAGEAbgBkACAAJABfAC4ARwBlAHQAUABhAHIAYQBtAGUAdABlAHIAcwAoACkAWwAwAF0ALgBQAGEAcgBhAG0AZQB0AGUAcgBUAHkAcABlAC4ATgBhAG0AZQAgAC0AZQBxACAAJwBJAEEAcwB5AG4AYwBPAHAAZQByAGEAdABpAG8AbgBgADEAJwAgAH0AKQBbADAAXQAKAAoARgB1AG4AYwB0AGkAbwBuACAAQQB3AGEAaQB0ACgAJABXAGkAbgBSAHQAVABhAHMAawAsACAAJABSAGUAcwB1AGwAdABUAHkAcABlACkAIAB7AAoAIAAgACAAIAAgACQAYQBzAFQAYQBzAGsAIAA9ACAAJABhAHMAVABhAHMAawBHAGUAbgBlAHIAaQBjAC4ATQBhAGsAZQBHAGUAbgBlAHIAaQBjAE0AZQB0AGgAbwBkACgAJABSAGUAcwB1AGwAdABUAHkAcABlACkACgAgACAAIAAgACAAJABuAGUAdABUAGEAcwBrACAAPQAgACQAYQBzAFQAYQBzAGsALgBJAG4AdgBvAGsAZQAoACQAbgB1AGwAbAAsACAAQAAoACQAVwBpAG4AUgB0AFQAYQBzAGsAKQApAAoAIAAgACAAIAAgACQAbgBlAHQAVABhAHMAawAuAFcAYQBpAHQAKAAtADEAKQAgAHwAIABPAHUAdAAtAE4AdQBsAGwACgAgACAAIAAgACAAJABuAGUAdABUAGEAcwBrAC4AUgBlAHMAdQBsAHQACgB9AAoACgBGAHUAbgBjAHQAaQBvAG4AIABBAHcAYQBpAHQAQQBjAHQAaQBvAG4AKAAkAFcAaQBuAFIAdABBAGMAdABpAG8AbgApACAAewAKACAAIAAgACAAIAAkAGEAcwBUAGEAcwBrACAAPQAgACgAWwBTAHkAcwB0AGUAbQAuAFcAaQBuAGQAbwB3AHMAUgB1AG4AdABpAG0AZQBTAHkAcwB0AGUAbQBFAHgAdABlAG4AcwBpAG8AbgBzAF0ALgBHAGUAdABNAGUAdABoAG8AZABzACgAKQAgAHwAIAA/ACAAewAgACQAXwAuAE4AYQBtAGUAIAAtAGUAcQAgACcAQQBzAFQAYQBzAGsAJwAgAC0AYQBuAGQAIAAkAF8ALgBHAGUAdABQAGEAcgBhAG0AZQB0AGUAcgBzACgAKQAuAEMAbwB1AG4AdAAgAC0AZQBxACAAMQAgAC0AYQBuAGQAIAAhACQAXwAuAEkAcwBHAGUAbgBlAHIAaQBjAE0AZQB0AGgAbwBkACAAfQApAFsAMABdAAoAIAAgACAAIAAgACQAbgBlAHQAVABhAHMAawAgAD0AIAAkAGEAcwBUAGEAcwBrAC4ASQBuAHYAbwBrAGUAKAAkAG4AdQBsAGwALAAgAEAAKAAkAFcAaQBuAFIAdABBAGMAdABpAG8AbgApACkACgAgACAAIAAgACAAJABuAGUAdABUAGEAcwBrAC4AVwBhAGkAdAAoAC0AMQApACAAfAAgAE8AdQB0AC0ATgB1AGwAbAAKAH0ACgAKAEYAdQBuAGMAdABpAG8AbgAgAFMAZQB0AEgAbwB0AHMAcABvAHQAKAAkAEUAbgBhAGIAbABlACkAIAB7AAoAIAAgACAAIAAgACQAYwBvAG4AbgBlAGMAdABpAG8AbgBQAHIAbwBmAGkAbABlACAAPQAgAFsAVwBpAG4AZABvAHcAcwAuAE4AZQB0AHcAbwByAGsAaQBuAGcALgBDAG8AbgBuAGUAYwB0AGkAdgBpAHQAeQAuAE4AZQB0AHcAbwByAGsASQBuAGYAbwByAG0AYQB0AGkAbwBuACwAVwBpAG4AZABvAHcAcwAuAE4AZQB0AHcAbwByAGsAaQBuAGcALgBDAG8AbgBuAGUAYwB0AGkAdgBpAHQAeQAsAEMAbwBuAHQAZQBuAHQAVAB5AHAAZQA9AFcAaQBuAGQAbwB3AHMAUgB1AG4AdABpAG0AZQBdADoAOgBHAGUAdABJAG4AdABlAHIAbgBlAHQAQwBvAG4AbgBlAGMAdABpAG8AbgBQAHIAbwBmAGkAbABlACgAKQAKACAAIAAgACAAIAAkAHQAZQB0AGgAZQByAGkAbgBnAE0AYQBuAGEAZwBlAHIAIAA9ACAAWwBXAGkAbgBkAG8AdwBzAC4ATgBlAHQAdwBvAHIAawBpAG4AZwAuAE4AZQB0AHcAbwByAGsATwBwAGUAcgBhAHQAbwByAHMALgBOAGUAdAB3AG8AcgBrAE8AcABlAHIAYQB0AG8AcgBUAGUAdABoAGUAcgBpAG4AZwBNAGEAbgBhAGcAZQByACwAVwBpAG4AZABvAHcAcwAuAE4AZQB0AHcAbwByAGsAaQBuAGcALgBOAGUAdAB3AG8AcgBrAE8AcABlAHIAYQB0AG8AcgBzACwAQwBvAG4AdABlAG4AdABUAHkAcABlAD0AVwBpAG4AZABvAHcAcwBSAHUAbgB0AGkAbQBlAF0AOgA6AEMAcgBlAGEAdABlAEYAcgBvAG0AQwBvAG4AbgBlAGMAdABpAG8AbgBQAHIAbwBmAGkAbABlACgAJABjAG8AbgBuAGUAYwB0AGkAbwBuAFAAcgBvAGYAaQBsAGUAKQAKAAoAIAAgACAAIAAgAGkAZgAgACgAJABFAG4AYQBiAGwAZQAgAC0AZQBxACAAMQApACAAewAKACAAIAAgACAAIAAgACAAIAAgAGkAZgAgACgAJAB0AGUAdABoAGUAcgBpAG4AZwBNAGEAbgBhAGcAZQByAC4AVABlAHQAaABlAHIAaQBuAGcATwBwAGUAcgBhAHQAaQBvAG4AYQBsAFMAdABhAHQAZQAgAC0AZQBxACAAMQApAAoAIAAgACAAIAAgACAAIAAgACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIgBIAG8AdABzAHAAbwB0ACAAaQBzACAAYQBsAHIAZQBhAGQAeQAgAE8AbgAhACIACgAgACAAIAAgACAAIAAgACAAIAB9AAoAIAAgACAAIAAgACAAIAAgACAAZQBsAHMAZQB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAiAEgAbwB0AHMAcABvAHQAIABpAHMAIABvAGYAZgAhACAAVAB1AHIAbgBpAG4AZwAgAGkAdAAgAG8AbgAiAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABBAHcAYQBpAHQAIAAoACQAdABlAHQAaABlAHIAaQBuAGcATQBhAG4AYQBnAGUAcgAuAFMAdABhAHIAdABUAGUAdABoAGUAcgBpAG4AZwBBAHMAeQBuAGMAKAApACkAIAAoAFsAVwBpAG4AZABvAHcAcwAuAE4AZQB0AHcAbwByAGsAaQBuAGcALgBOAGUAdAB3AG8AcgBrAE8AcABlAHIAYQB0AG8AcgBzAC4ATgBlAHQAdwBvAHIAawBPAHAAZQByAGEAdABvAHIAVABlAHQAaABlAHIAaQBuAGcATwBwAGUAcgBhAHQAaQBvAG4AUgBlAHMAdQBsAHQAXQApAAoAIAAgACAAIAAgACAAIAAgACAAfQAKACAAIAAgACAAIAB9AAoAIAAgACAAIAAgAGUAbABzAGUAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAaQBmACAAKAAkAHQAZQB0AGgAZQByAGkAbgBnAE0AYQBuAGEAZwBlAHIALgBUAGUAdABoAGUAcgBpAG4AZwBPAHAAZQByAGEAdABpAG8AbgBhAGwAUwB0AGEAdABlACAALQBlAHEAIAAwACkACgAgACAAIAAgACAAIAAgACAAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAiAEgAbwB0AHMAcABvAHQAIABpAHMAIABhAGwAcgBlAGEAZAB5ACAATwBmAGYAIQAiAAoAIAAgACAAIAAgACAAIAAgACAAfQAKACAAIAAgACAAIAAgACAAIAAgAGUAbABzAGUAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIgBIAG8AdABzAHAAbwB0ACAAaQBzACAAbwBuACEAIABUAHUAcgBuAGkAbgBnACAAaQB0ACAAbwBmAGYAIgAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAQQB3AGEAaQB0ACAAKAAkAHQAZQB0AGgAZQByAGkAbgBnAE0AYQBuAGEAZwBlAHIALgBTAHQAbwBwAFQAZQB0AGgAZQByAGkAbgBnAEEAcwB5AG4AYwAoACkAKQAgACgAWwBXAGkAbgBkAG8AdwBzAC4ATgBlAHQAdwBvAHIAawBpAG4AZwAuAE4AZQB0AHcAbwByAGsATwBwAGUAcgBhAHQAbwByAHMALgBOAGUAdAB3AG8AcgBrAE8AcABlAHIAYQB0AG8AcgBUAGUAdABoAGUAcgBpAG4AZwBPAHAAZQByAGEAdABpAG8AbgBSAGUAcwB1AGwAdABdACkACgAgACAAIAAgACAAIAAgACAAIAB9AAoAIAAgACAAIAAgAH0ACgB9AAoACgBTAGUAdABIAG8AdABzAHAAbwB0ACgAMQApAAoA"


def sc():
    image = ImageGrab.grab()
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    image.save(f"{SS_FOLDER}\\{current_datetime}.png")
    print("SCREENSHOT SAVED")


def execute_command(command):
    try:
        print(f"Executing: {command}")
        if command == "ss":
            print("taking SCREENSHOT")
            sc()
            return "SCREENSHOT SAVED"

        elif command.lower().startswith("start "):
            program = command[6:].strip()
            subprocess.Popen(program, shell=True)
            return f"Background process started: {program}"

        else:
            # Added timeout to prevent freezing on inputs
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip()

    except subprocess.CalledProcessError as e:
        return f"ERROR: Command failed.\nSTDERR: {e.stderr.strip()}"
    except Exception as e:
        return f"ERROR: {e}"


def is_hotspot_active():
    """
    Checks if the default hotspot IP exists in ipconfig.
    """
    try:
        output = subprocess.check_output("ipconfig", text=True)
        if HOTSPOT_IP in output:
            return True
        return False
    except:
        return False


def turn_on_hotspot():
    print("Attempting to turn on Mobile Hotspot...")
    command_args = [
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "-encodedCommand",
        encd_cmd,
    ]
    subprocess.Popen(command_args, creationflags=subprocess.CREATE_NO_WINDOW)


def start_server():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen()
            print(f"Server LISTENING on {HOST}:{PORT}.")

            while True:
                conn, addr = s.accept()
                with conn:
                    print(f"Connected by : {addr}")
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        command = data.decode("utf-8").strip()
                        print(f"Received: '{command}'")
                        response_str = execute_command(command)
                        conn.sendall(response_str.encode("utf-8"))
                        print(f"Sent response...")
    except Exception as e:
        print(f"Server Error: {e}")


if __name__ == "__main__":
    print("--- SYSTEM CONTROL STARTED ---")

    while True:
        if is_hotspot_active():
            print("Hotspot detected (192.168.137.1). Starting Server...")
            start_server()
        else:
            print("Hotspot not detected. Turning it on...")
            turn_on_hotspot()

            print("Waiting 10 seconds for adapter to initialize...")
            time.sleep(10)
