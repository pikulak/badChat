#!c:/python34/python.exe
import socket
from base64 import b64decode
import json
from time import sleep
from collections import defaultdict
from _thread import start_new_thread
from util import switch
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('192.168.1.102',8000))
sock.listen(50)
quit = True
list_connections = [] # shared between connection threads

def delUser(dict, value): #value=ip address
    name = dict[value]
    try:
        del dict[value]
        del dict[name]
        return True
    except KeyError:
        return False
    
class Server():
    def __init__(self, srvAddr):
        self.auth_users = {}
        self.srvAddr = srvAddr #tuple
    
    def createSocket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(self.srvAddr)
        self.sock.listen(50)
        
    def auth(self, data, connection):
        global list_connections
        if data['name'] in self.auth_users:
            print('Failed to login,existing user, ip=',connection.getpeername()[0],'user=',data['name']) # SOME LOG STUFF
            return 'BAD', 'User exists'
        else:
            self.auth_users[data['name']] = connection
            self.auth_users[self.connStrRepr(connection)] = data['name']
            list_connections.append(connection)
            print("Loged in:",data['name'])  # SOME LOG STUFF
            return 'OK!', 'Successful login'
    
    def connStrRepr(self, connection):
        return connection.getpeername()[0]+":"+str(connection.getpeername()[1])
    
    def msgAll(self, data, sender_connection):
        message = self.auth_users[self.connStrRepr(sender_connection)] +'> '+ data['message']
        print(message)
        global list_connections
        for connection in list_connections:
            if connection != sender_connection:
                print('sent to',connection)  # SOME LOG STUFF
                connection.sendall(b'OK!'+ message.encode('utf8'))
        return 'OK!', 'Messages sent to all'
                
    def proccessData(self, data, flag,connection):
        data = json.loads(data)
        response = ''
        for case in switch(flag):
            if case(1):
                response = self.auth(data, connection)
                break
            if case(2):
                response = self.msgAll(data, connection)
        return response
        
    def getData(self, connection, size):
        recv_data = b''
        while len(recv_data)<size:
            try:
                packet = connection.recv(size - len(recv_data))
            except(ConnectionResetError, ConnectionAbortedError):
                return 'Disconnected by client'
            if not packet:
                return None
            recv_data += packet
        return recv_data.decode('utf8')
        
    def validHeaders(self, headers):
        if not headers['Length'] and type(headers['Length']) is not int:   return False
        if not headers['Flag'] and type(headers['Flag']) is not int:   return False
        if not headers['Date']:   return False
        if not headers['Data-type']and type(headers['Data-type']) is not str:   return False
        return True
        
    def getHeaders(self, package):
        headers = package
        headers = headers.decode('utf-8')
        headers = json.loads(b64decode(headers).decode('utf-8'))
        return headers
        
    def doResponse(self, connection, len, flag):
        try:
            connection.sendall(b'')
        except(ConnectionResetError, ConnectionAbortedError):
            return 'Disconnected by client'
        data = self.getData(connection, len)
       
        if data == 'Disconnected by client':
            return data
        else:
            print(data)  # SOME DEBUG STUFF
        response = self.proccessData(data, flag, connection)
        connection.sendall(response[0].encode('utf8'))
        return response[1]
            
    def clientThread(self, connection):
        act_addr = self.connStrRepr(connection)
        while True:
            try:
                package = connection.recv(100)
     
            except (ConnectionResetError, ConnectionAbortedError):
                msg = 'Disconnected by client'
                break
            if len(package) > 1:
                headers = self.getHeaders(package)
      
            else:
                msg = 'Bad data'
                break
            
            if self.validHeaders(headers):
                r = self.doResponse(connection, headers['Length'], headers['Flag']) == 'User exists'
                msg = r
                if msg == 'Messages sent to all':
                    name = self.auth_users[act_addr]
                    print('Message from',name, 'to all') # SOME DEBUG STUFF
                if msg == 'Successful login':
                    name = self.auth_users[act_addr]
                    print('Successful login from', act_addr, 'as', name) # SOME DEBUG STUFF
                if msg == 'User exists':
                    break
                if msg == 'Disconnected by client':
                    break
            else:
                print("Disconnected: ", connection.getpeername(),'code=', 0) # SOME DEBUG STUFF
                connection.sendall(b'BAD') # SOME DEBUG STUFF
                break # SOME DEBUG STUFF
                
        if msg == 'Successful login':
            name = self.auth_users[act_addr] # connection.getpeername[0] = ip addr
            if name:
                if delUser(self.auth_users, act_addr):
                    list_connections.remove(connection)
                    msg = "Successful disconnected by server, user="+name+"(addr="+ act_addr + "), " + "code=1" # when disconnected with name
                    print(msg) # SOME DEBUG STUFF
                    
        if msg == 'User exists':
            msg = "Successful disconnected by server, addr="+act_addr+ ", code=0" #while connected without name
            print(msg) # SOME DEBUG STUFF
            
        if msg == 'Disconnected by client':
            try:
                name = self.auth_users[act_addr]
                delUser(self.auth_users, act_addr)
                list_connections.remove(connection)
                print(msg, act_addr) # SOME DEBUG STUFF
            except KeyError:
                print(msg, act_addr) # SOME DEBUG STUFF
        if msg == 'Bad data':
            print('Bad data',act_addr) # SOME DEBUG STUFF
        connection.close() 
        
    def authUserPrinter(self):
        lenTmp = 0
        global list_connections
        print('Initializing authUserPrinter...') # SOME DEBUG STUFF
        while True:
            sleep(0.5)
            now = len(list_connections)
            if lenTmp != now:
                lenTmp = now
                print(list_connections) # SOME DEBUG STUFF
    
    def run(self):
        self.createSocket()
        
        start_new_thread(self.authUserPrinter,())
        while True:
            connection, none = self.sock.accept()
            print('Connected! ', connection.getpeername()) # SOME DEBUG STUFF
            start_new_thread(self.clientThread,(connection,))
Server(('192.168.1.102', 8002)).run()
