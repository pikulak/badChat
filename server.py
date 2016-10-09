﻿#!c:/python34/python.exe
"""
This module does server stuff.
Author: Kacper Pikulski @ pikulak1@gmail.com
"""
import socket
import json
from base64 import b64decode
from time import sleep
from _thread import start_new_thread
# Shared between connection threads
list_connections = []  #


def delUser(dict, value):
    """Value = ipaddr. Deleting two keys from two-way dict.
    """
    name = dict[value]
    try:
        del dict[value]
        del dict[name]
        return True
    except KeyError:
        return False

        
class Server():
    """Header={
            'Length' : int
            'Flag' : int
            'Date' : str
            'Data-type' : str}
    """
    def __init__(self, server_address):
        #Two-way dict.
        self.auth_users = {}
        #Tuple.
        self.server_address = server_address

    def create_socket(self):
        """Creating socket.
        """
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(self.server_address)
        self.sock.listen(50)
    
    def auth(self, data, connection):
        """Auth function. Takes data and socket object.
        """
        
        global list_connections
        #Checking if username already in using
        if data['name'] in self.auth_users:
            #Failed login.
            print(
                'Failed to login,existing user, ip=',
                connection.getpeername()[0],
                'user=',
                data['name'])
            return 'BAD', 'User exists'
        else:
            #Successful login.
            self.auth_users[data['name']] = connection
            self.auth_users[self.conn_str_repr(connection)] = data['name']
            list_connections.append(connection)
            print("Loged in:", data['name'])  # SOME DEBUG STUFF
            return 'OK!', 'Successful login'
    
    def conn_str_repr(self, connection):
        """Two-way dict object's key representation.
        """
        
        return connection.getpeername()[0] + \
            ":" + str(connection.getpeername()[1])
            
    def send_to_all(self, data, sender_connection):
        """Sending message to all connected peers without the sender.
           TODO send message as json {'message':blabla, 'from':sender}.
        """
        
        global list_connections
        message = self.auth_users[self.conn_str_repr(sender_connection)] + '> ' + data['message']
        for connection in list_connections:
            if connection != sender_connection:
                connection.sendall(b'OK!' + message.encode('utf8'))
        return 'OK!', 'Messages sent to all'
        
    def proccess_data(self, data, flag, connection):
        """Handling flags.
        """
        
        data = json.loads(data)
        response = ''
        if flag == 1:
            response = self.auth(data, connection)
        if flag == 2:
            response = self.send_to_all(data, connection)
        return response
        
    def get_data(self, connection, size):
        """Getting data. If can't then return error message.
           Return data if all went good
        """
        
        recv_data = b''
        while len(recv_data) < size:
            try:
                packet = connection.recv(size - len(recv_data))
            except(ConnectionResetError, ConnectionAbortedError):
                return 'Disconnected by client'
            if not packet:
                return None
            recv_data += packet
        return recv_data.decode('utf8')
       
    def valid_headers(self, headers):
        """Check for correct types of header's fields
        """
        
        if not headers['Length'] and not isinstance(headers['Length'], int):
            return False
        if not headers['Flag'] and not isinstance(headers['Flag'], int):
            return False
        if not headers['Date']:
            return False
        if not headers['Data-type'] and not isinstance(headers['Data-type'], str):
            return False
        return True
        
    def get_headers(self, package):
        """Decode, load to json and return.
        """
        
        headers = package
        headers = headers.decode('utf-8')
        headers = json.loads(b64decode(headers).decode('utf-8'))
        return headers
        
    def do_response(self, connection, len, flag):
        """Trying to check if connection is alive
           If not then return error message
           If cannot receive data then return error message
           Response is a tuple with ('BAD' or 'OK!', DEBUGmessage)
           If all went good then send 'OK!' otherwise send 'BAD' which doesn't matter now
           TODO make 'OK!' and 'BAD!' matter something
           Return DEBUGmessage
        """
        try:
            connection.sendall(b'')
        except(ConnectionResetError, ConnectionAbortedError):
            return 'Disconnected by client'
            
        data = self.get_data(connection, len)
        if data == 'Disconnected by client':
            return data
            
        response = self.proccess_data(data, flag, connection)
        connection.sendall(response[0].encode('utf8'))
        return response[1]
    
    def client_thread(self, connection):
        """Client thread.
        """
        
        connection_address = self.conn_str_repr(connection)
        while True:
            try:
                #Grab a header.
                package = connection.recv(100)
            except (ConnectionResetError, ConnectionAbortedError):
                #Disconnected or something went wrong from client
                msg = 'Disconnected by client'
                break
                
            #I dont want null... 
            if len(package) > 1:
                headers = self.get_headers(package)

            else:
                msg = 'Bad data'  #No it's not, I have to change it.
                break

            if self.valid_headers(headers):
                r = self.do_response(
                    connection,
                    headers['Length'],
                    headers['Flag'])
                #I know, tell me about it
                msg = r
                
                if msg == 'Messages sent to all':
                    name = self.auth_users[connection_address]
                    print('Message from', name, 'to all')
                if msg == 'Successful login':
                    name = self.auth_users[connection_address]
                    print(
                        'Successful login from',
                        connection_address,
                        'as',
                        name)
                if msg == 'User exists':
                    break
                if msg == 'Disconnected by client':
                    break
            else:
                print(
                    "Disconnected: ",
                    connection.getpeername(),
                    'code=',
                    0) 
                connection.sendall(b'BAD')
                break 

        # Finally, let it print something useful.
        if msg == 'Successful login':
            # connection.getpeername[0] = ip addr
            name = self.auth_users[connection_address]
            if name:
                if delUser(self.auth_users, connection_address):
                    list_connections.remove(connection)
                    #If logout.
                    msg = "Successful disconnected by server, user=" + name + \
                        "(addr=" + connection_address + "), " + "code=1"  
                    print(msg) 

        if msg == 'User exists':
            #Disconnect if failed to login, because user exist.
            #TODO attemps
            msg = "Successful disconnected by server, addr=" + \
                connection_address + ", code=0"  
            print(msg)

        if msg == 'Disconnected by client':
            try:
                name = self.auth_users[connection_address]
                delUser(self.auth_users, connection_address)
                list_connections.remove(connection)
                print(msg, connection_address)
            except KeyError:
                print(msg, connection_address)
        if msg == 'Bad data':
            print('Bad data', connection_address)
        #Fine.
        connection.close()
        
    #Helper.
    def authUserPrinter(self):
        lenTmp = 0
        global list_connections
        print('Initializing authUserPrinter...')  
        while True:
            sleep(0.5)
            now = len(list_connections)
            if lenTmp != now:
                lenTmp = now
                print(list_connections)  
                
    #Run Forest run!
    def run(self):
        self.create_socket()
        start_new_thread(self.authUserPrinter, ())
        while True:
            connection, none = self.sock.accept()
            print('Connected! ', connection.getpeername())
            start_new_thread(self.client_thread, (connection,))
Server(('192.168.1.102', 8002)).run()
