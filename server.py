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

encd_cmd = "WwBXAGkAbgBkAG8AdwBzAC4AUwB5AHMAdABlAG0ALgBVAHMAZQByAFAAcgBvAGYAaQBsAGUALgBMAG8AYwBrAFMAYwByAGUAZQBuACwAVwBpAG4AZABvAHcAcwAuAFMAeQBzAHQAZQBtAC4AVQBzAGUAcgBQAHIAbwBmAGkAbABlACwAQwBvAG4AdABlAG4AdABUAHkAcABlAD0AVwBpAG4AZABvAHcAcwBSAHUAbgB0AGkAbQBlAF0AIAB8ACAATwB1AHQALQBOAHUAbABsAA0ACgBBAGQAZAAtAFQAeQBwAGUAIAAtAEEAcwBzAGUAbQBiAGwAeQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4AVwBpAG4AZABvAHcAcwBSAHUAbgB0AGkAbQBlAA0ACgAkAGEAcwBUAGEAcwBrAEcAZQBuAGUAcgBpAGMAIAA9ACAAKABbAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwBSAHUAbgB0AGkAbQBlAFMAeQBzAHQAZQBtAEUAeAB0AGUAbgBzAGkAbwBuAHMAXQAuAEcAZQB0AE0AZQB0AGgAbwBkAHMAKAApACAAfAAgAD8AIAB7ACAAJABfAC4ATgBhAG0AZQAgAC0AZQBxACAAJwBBAHMAVABhAHMAawAnACAALQBhAG4AZAAgACQAXwAuAEcAZQB0AFAAYQByAGEAbQBlAHQAZQByAHMAKAApAC4AQwBvAHUAbgB0ACAALQBlAHEAIAAxACAALQBhAG4AZAAgACQAXwAuAEcAZQB0AFAAYQByAGEAbQBlAHQAZQByAHMAKAApAFsAMABdAC4AUABhAHIAYQBtAGUAdABlAHIAVAB5AHAAZQAuAE4AYQBtAGUAIAAtAGUAcQAgACcASQBBAHMAeQBuAGMATwBwAGUAcgBhAHQAaQBvAG4AYAAxACcAIAB9ACkAWwAwAF0ADQAKAEYAdQBuAGMAdABpAG8AbgAgAEEAdwBhAGkAdAAoACQAVwBpAG4AUgB0AFQAYQBzAGsALAAgACQAUgBlAHMAdQBsAHQAVAB5AHAAZQApACAAewANAAoAIAAgACAAIAAkAGEAcwBUAGEAcwBrACAAPQAgACQAYQBzAFQAYQBzAGsARwBlAG4AZQByAGkAYwAuAE0AYQBrAGUARwBlAG4AZQByAGkAYwBNAGUAdABoAG8AZAAoACQAUgBlAHMAdQBsAHQAVAB5AHAAZQApAA0ACgAgACAAIAAgACQAbgBlAHQAVABhAHMAawAgAD0AIAAkAGEAcwBUAGEAcwBrAC4ASQBuAHYAbwBrAGUAKAAkAG4AdQBsAGwALAAgAEAAKAAkAFcAaQBuAFIAdABUAGEAcwBrACkAKQANAAoAIAAgACAAIAAkAG4AZQB0AFQAYQBzAGsALgBXAGEAaQB0ACgALQAxACkAIAB8ACAATwB1AHQALQBOAHUAbABsAA0ACgAgACAAIAAgACQAbgBlAHQAVABhAHMAawAuAFIAZQBzAHUAbAB0AA0ACgB9AA0ACgBGAHUAbgBjAHQAaQBvAG4AIABBAHcAYQBpAHQAQQBjAHQAaQBvAG4AKAAkAFcAaQBuAFIAdABBAGMAdABpAG8AbgApACAAewANAAoAIAAgACAAIAAkAGEAcwBUAGEAcwBrACAAPQAgACgAWwBTAHkAcwB0AGUAbQAuAFcAaQBuAGQAbwB3AHMAUgB1AG4AdABpAG0AZQBTAHkAcwB0AGUAbQBFAHgAdABlAG4AcwBpAG8AbgBzAF0ALgBHAGUAdABNAGUAdABoAG8AZABzACgAKQAgAHwAIAA/ACAAewAgACQAXwAuAE4AYQBtAGUAIAAtAGUAcQAgACcAQQBzAFQAYQBzAGsAJwAgAC0AYQBuAGQAIAAkAF8ALgBHAGUAdABQAGEAcgBhAG0AZQB0AGUAcgBzACgAKQAuAEMAbwB1AG4AdAAgAC0AZQBxACAAMQAgAC0AYQBuAGQAIAAhACQAXwAuAEkAcwBHAGUAbgBlAHIAaQBjAE0AZQB0AGgAbwBkACAAfQApAFsAMABdAA0ACgAgACAAIAAgACQAbgBlAHQAVABhAHMAawAgAD0AIAAkAGEAcwBUAGEAcwBrAC4ASQBuAHYAbwBrAGUAKAAkAG4AdQBsAGwALAAgAEAAKAAkAFcAaQBuAFIAdABBAGMAdABpAG8AbgApACkADQAKACAAIAAgACAAJABuAGUAdABUAGEAcwBrAC4AVwBhAGkAdAAoAC0AMQApACAAfAAgAE8AdQB0AC0ATgB1AGwAbAANAAoAfQANAAoAJABjAG8AbgBuAGUAYwB0AGkAbwBuAFAAcgBvAGYAaQBsAGUAIAA9ACAAWwBXAGkAbgBkAG8AdwBzAC4ATgBlAHQAdwBvAHIAawBpAG4AZwAuAEMAbwBuAG4AZQBjAHQAaQB2AGkAdAB5AC4ATgBlAHQAdwBvAHIAawBJAG4AZgBvAHIAbQBhAHQAaQBvAG4ALABXAGkAbgBkAG8AdwBzAC4ATgBlAHQAdwBvAHIAawBpAG4AZwAuAEMAbwBuAG4AZQBjAHQAaQB2AGkAdAB5ACwAQwBvAG4AdABlAG4AdABUAHkAcABlAD0AVwBpAG4AZABvAHcAcwBSAHUAbgB0AGkAbQBlAF0AOgA6AEcAZQB0AEkAbgB0AGUAcgBuAGUAdABDAG8AbgBuAGUAYwB0AGkAbwBuAFAAcgBvAGYAaQBsAGUAKAApAA0ACgAkAHQAZQB0AGgAZQByAGkAbgBnAE0AYQBuAGEAZwBlAHIAIAA9ACAAWwBXAGkAbgBkAG8AdwBzAC4ATgBlAHQAdwBvAHIAawBpAG4AZwAuAE4AZQB0AHcAbwByAGsATwBwAGUAcgBhAHQAbwByAHMALgBOAGUAdAB3AG8AcgBrAE8AcABlAHIAYQB0AG8AcgBUAGUAdABoAGUAcgBpAG4AZwBNAGEAbgBhAGcAZQByACwAVwBpAG4AZABvAHcAcwAuAE4AZQB0AHcAbwByAGsAaQBuAGcALgBOAGUAdAB3AG8AcgBrAE8AcABlAHIAYQB0AG8AcgBzACwAQwBvAG4AdABlAG4AdABUAHkAcABlAD0AVwBpAG4AZABvAHcAcwBSAHUAbgB0AGkAbQBlAF0AOgA6AEMAcgBlAGEAdABlAEYAcgBvAG0AQwBvAG4AbgBlAGMAdABpAG8AbgBQAHIAbwBmAGkAbABlACgAJABjAG8AbgBuAGUAYwB0AGkAbwBuAFAAcgBvAGYAaQBsAGUAKQANAAoADQAKACMAIABCAGUAIABzAHUAcgBlACAAdABvACAAaQBuAGMAbAB1AGQAZQAgAEIAZQBuACAATgAuACcAcwAgAGEAdwBhAGkAdAAgAGYAbwByACAASQBBAHMAeQBuAGMATwBwAGUAcgBhAHQAaQBvAG4AOgANAAoAIwAgAGgAdAB0AHAAcwA6AC8ALwBzAHUAcABlAHIAdQBzAGUAcgAuAGMAbwBtAC8AcQB1AGUAcwB0AGkAbwBuAHMALwAxADMANAAxADkAOQA3AC8AdQBzAGkAbgBnAC0AYQAtAHUAdwBwAC0AYQBwAGkALQBuAGEAbQBlAHMAcABhAGMAZQAtAGkAbgAtAHAAbwB3AGUAcgBzAGgAZQBsAGwADQAKAA0ACgAjACAAQwBoAGUAYwBrACAAdwBoAGUAdABoAGUAcgAgAE0AbwBiAGkAbABlACAASABvAHQAcwBwAG8AdAAgAGkAcwAgAGUAbgBhAGIAbABlAGQADQAKACQAdABlAHQAaABlAHIAaQBuAGcATQBhAG4AYQBnAGUAcgAuAFQAZQB0AGgAZQByAGkAbgBnAE8AcABlAHIAYQB0AGkAbwBuAGEAbABTAHQAYQB0AGUADQAKAA0ACgAjACAAUwB0AGEAcgB0ACAATQBvAGIAaQBsAGUAIABIAG8AdABzAHAAbwB0AA0ACgBBAHcAYQBpAHQAIAAoACQAdABlAHQAaABlAHIAaQBuAGcATQBhAG4AYQBnAGUAcgAuAFMAdABhAHIAdABUAGUAdABoAGUAcgBpAG4AZwBBAHMAeQBuAGMAKAApACkAIAAoAFsAVwBpAG4AZABvAHcAcwAuAE4AZQB0AHcAbwByAGsAaQBuAGcALgBOAGUAdAB3AG8AcgBrAE8AcABlAHIAYQB0AG8AcgBzAC4ATgBlAHQAdwBvAHIAawBPAHAAZQByAGEAdABvAHIAVABlAHQAaABlAHIAaQBuAGcATwBwAGUAcgBhAHQAaQBvAG4AUgBlAHMAdQBsAHQAXQApAA=="


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
