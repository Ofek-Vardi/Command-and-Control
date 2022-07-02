# Python C2 Project

## Description

This command and control project contains both the server & client sides.
Once communication is established, it allows command execution on the client side,
as well as uploading / downloading files between the client and server.\

All communication is done over `AF_INET, SOCK_STREAM` sockets (IPv4, TCP).
TCP  methodology is imlemented when sending commands / receiving output, by appending headers of set size to every message.
Data segmentation and integrity verification are both implemented when downloading / uploading files.

Both scripts are extremely modular as most values are configured through the use of global variables.
The option to import values through a json file will be added in a later release.

## Installation

    git clone https://github.com/Ofek-Vardi/Command-and-Control.git
    pip install -r requirements.txt
    python3 server.py

## Full Imports List

**Client side:**

    - socket
    - os
    - sys
    - pathlib
    - hashlib
    - time
    - random
    - subprocess

**Server side:**

    - socket
    - os
    - pathlib
    - hashlib
    - termcolor
    - threading
    - logging
    - prettytable.PrettyTable

## Keyword Commands

**Session handling keywords:**

> `exit` / `quit`: Close the server side script.\
> `clear`: Clear server side terminal screen.\
> `sessions`: Display all active sessions.\
> `sessions -i SESSION_ID`: Reattach the specified session.\
> `broadcast COMMAND`: Execute a command on all available targets.

**Client session keywords:**

> `background` / `bg`: Background shell and keep the current session active.\
> `quit` / `exit`: Exit shell and close the current session.\
> `clear`: Clear server side terminal screen.\
> `download TARGET_FILE_PATH`: Download target file from client to server.\
> `upload TARGET_FILE_PATH`: Upload target file from server to client.\
> `kill`: Signal the client side to terminate itself.
