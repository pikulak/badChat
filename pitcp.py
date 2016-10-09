#!c:/python34/python.exe
import socket
import errors
from base64 import b64encode
import json
def send(headers, data, sock):
    headers = b64encode(json.dumps(headers).encode('utf8'))
    sock.sendall(headers)
    sock.sendall(json.dumps(data).encode('utf8'))
