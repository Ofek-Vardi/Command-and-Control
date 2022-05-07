# Python C2 Project

## Description

This command and control project contains both the server & client sides.\
Once communication is established, it allows command execution on the client side,\
as well as uploading / downloading files between the client and server.\

All communication is done over `AF_INET, SOCK_STREAM` sockets (IPv4, TCP).\
TCP  methodology is imlemented when sending commands / receiving output, by appending headers of set size to every messages.\
Data segmentation and integrity verification are implemented when downloading / uploading files.

Both scripts are extremely modular as most values are configured through the use of global variables.\
The option to import values through a json file will be added in a later release.

## Imports

**Client side:**

    - socket
    - os
    - pathlib
    - hashlib
    - time
    - random
    - subprocess

**Server side:**

    - socket
    - os
    - platform
    - pathlib
    - hashlib
    - datetime
    - termcolor

## Keyword Commands

The following keywords are recognized by both client and server side for their respective actions:
>`quit` / `exit`: Exit the current shell.\
>`clear`: Clear server side terminal screen.\
>`download TARGET_FILE_PATH`: Download target file from client to server.\
>`upload TARGET_FILE_PATH`: Upload target file from server to client.
