#!c:/python34/python.exe
#
#This module does server stuff.
#Author: Kacper Pikulski @ pikulak1@gmail.com
#
#
import socket
import json
from base64 import b64decode
from time import sleep
from collections import defaultdict
from _thread import start_new_thread
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('192.168.1.102', 8000))
sock.listen(50)
quit = True
# Shared between connection threads
list_connections = []  #

#Value = ipaddr. Deleting two keys from two-way dict.
def delUser(dict, value):  
    name = dict[value]
    try:
        del dict[value]
        del dict[name]
        return True
    except KeyError:
        return False


class Server():

    def __init__(self, srvAddr):
        #Two-way dict.
        self.auth_users = {}
        #Tuple.
        self.srvAddr = srvAddr

    def createSocket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(self.srvAddr)
        self.sock.listen(50)
    
    #Auth function. Takes data and socket object.
    def auth(self, data, connection):
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
            self.auth_users[self.connStrRepr(connection)] = data['name']
            list_connections.append(connection)
            print("Loged in:", data['name'])  # SOME DEBUG STUFF
            return 'OK!', 'Successful login'
    
    #Just for two-way dict object's key representation
    def connStrRepr(self, connection):
        return connection.getpeername()[0] + \
            ":" + str(connection.getpeername()[1])
            
    #Sending message to all connected peers without the sender.
    #TODO send message as json {'message':blabla, 'from':sender}.
    def msgAll(self, data, sender_connection):
        global list_connections
        message = self.auth_users[self.connStrRepr(sender_connection)] + '> ' + data['message']
        for connection in list_connections:
            if connection != sender_connection:
                connection.sendall(b'OK!' + message.encode('utf8'))
        return 'OK!', 'Messages sent to all'
        
    #Handling flags.
    def proccessData(self, data, flag, connection):
        data = json.loads(data)
        response = ''
        if flag == 1:
            response = self.auth(data, connection)
        if flag == 2:
            response = self.msgAll(data, connection)
        return response
        
    #Getting data. If can't then return error message.
    #Return data if all went good
    def getData(self, connection, size):
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
        
    #Check for correct types of header's fields
    def validHeaders(self, headers):
        if not headers['Length'] and not isinstance(headers['Length'], int):
            return False
        if not headers['Flag'] and not isinstance(headers['Flag'], int):
            return False
        if not headers['Date']:
            return False
        if not headers['Data-type'] and not isinstance(headers['Data-type'], str):
            return False
        return True
        
    #Decode, load to json and return
    def getHeaders(self, package):
        headers = package
        headers = headers.decode('utf-8')
        headers = json.loads(b64decode(headers).decode('utf-8'))
        return headers
        
    #Trying to check if connection is alive
    #If not then return error message
    #If cannot receive data then return error message
    #Response is a tuple with ('BAD' or 'OK!', DEBUGmessage)
    #If all went good then send 'OK!' otherwise send 'BAD' which doesn't matter now
    #TODO make 'OK!' and 'BAD!' matter something
    #Return DEBUGmessage
    def doResponse(self, connection, len, flag):
        try:
            connection.sendall(b'')
        except(ConnectionResetError, ConnectionAbortedError):
            return 'Disconnected by client'
            
        data = self.getData(connection, len)
        if data == 'Disconnected by client':
            return data
            
        response = self.proccessData(data, flag, connection)
        connection.sendall(response[0].encode('utf8'))
        return response[1]
    
    def clientThread(self, connection):
        act_addr = self.connStrRepr(connection)
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
                headers = self.getHeaders(package)

            else:
                msg = 'Bad data'  #No it's not, I have to change it.
                break

            if self.validHeaders(headers):
                r = self.doResponse(
                    connection,
                    headers['Length'],
                    headers['Flag'])
                #I know, tell me about it
                msg = r
                
                if msg == 'Messages sent to all':
                    name = self.auth_users[act_addr]
                    print('Message from', name, 'to all')
                if msg == 'Successful login':
                    name = self.auth_users[act_addr]
                    print(
                        'Successful login from',
                        act_addr,
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
            name = self.auth_users[act_addr]
            if name:
                if delUser(self.auth_users, act_addr):
                    list_connections.remove(connection)
                    msg = "Successful disconnected by server, user=" + name + \
                        "(addr=" + act_addr + "), " + "code=1"  # when disconnected with name
                    print(msg)  # SOME DEBUG STUFF

        if msg == 'User exists':
            msg = "Successful disconnected by server, addr=" + \
                act_addr + ", code=0"  # while connected without name
            print(msg)

        if msg == 'Disconnected by client':
            try:
                name = self.auth_users[act_addr]
                delUser(self.auth_users, act_addr)
                list_connections.remove(connection)
                print(msg, act_addr)
            except KeyError:
                print(msg, act_addr)
        if msg == 'Bad data':
            print('Bad data', act_addr)
        #Fine.
        connection.close()
        
    #Helper.
    def authUserPrinter(self):
        lenTmp = 0
        global list_connections
        print('Initializing authUserPrinter...')  # SOME DEBUG STUFF
        while True:
            sleep(0.5)
            now = len(list_connections)
            if lenTmp != now:
                lenTmp = now
                print(list_connections)  # SOME DEBUG STUFF
    #Run Forest run!
    def run(self):
        self.createSocket()
        start_new_thread(self.authUserPrinter, ())
        while True:
            connection, none = self.sock.accept()
            print('Connected! ', connection.getpeername())
            start_new_thread(self.clientThread, (connection,))
Server(('192.168.1.102', 8002)).run()
