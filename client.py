#!c:/python34/python.exe

from datetime import datetime
from pitcp import send
from _thread import start_new_thread
import json
import sys
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('192.168.1.102', 8002))


def prepareHeaders(len, flag, type):
    return {
        'Length': len,
        'Flag': flag,
        'Date': str(datetime.now().strftime("%Y-%m-%d %H:%M")),
        'Data-type': type,
    }


def receive(nothing):
    while True:
        message = sock.recv(1024).decode('utf8')

        if message:
            print(message[3:])


def prepareData(**kwargs):
    data = {}
    for key, value in kwargs.items():
        data[key] = value
    return data


def auth(name):
    data = prepareData(name=name)
    headers = prepareHeaders(len(str(data)), 1, 'json')
    send(headers, data, sock)
    if sock.recv(3).decode('utf8') == 'OK!':
        print('Loged in!')
        return True
    else:
        print('Cant log-in:// Try again or type "quit"')
        return False

nameInp = input("Enter username:")
auth(nameInp)
nothing = 0
start_new_thread(receive, (nothing,))
while True:
    inp = input(nameInp.strip() + ">")
    data = prepareData(message=inp)
    headers = prepareHeaders(len(str(data)), 2, 'json')

    send(headers, data, sock)
    if inp == 'q':
        break
sock.close()
