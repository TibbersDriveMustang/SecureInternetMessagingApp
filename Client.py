import socket
import sys
from Crypto.Hash import SHA256
from Tkinter import *

#public key encryption
from Crypto.Cipher import  DES3
from Crypto.Cipher import blockalgo

import pickle
import json

class commands:
    START = '1'
    AUTHEN = '2'
    STOP = '3'

class Client:
    clientPassword = [11]
    def __init__(self):
        #Create a TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #Password GUI
        self.master = Tk()
        #Password input column
        Label(self.master, text = "Input Password").grid(row = 0)
        self.e1 = Entry(self.master)
        self.e1.grid(row = 0, column = 1)
        #Password input button
        self.button = Button(self.master, width = 10, padx = 3, pady = 3)
        self.button["text"] = "Enter"
        self.button["command"] = self.comparePWD
        self.button.grid(row = 1, column = 0, padx = 2, pady = 2)


        #Password Hash
        self.passwordHash = SHA256.new('hxg140630').digest()
        self.start()
        mainloop()

    def start(self):
        #Load Server Public Key
        self.serverPublicKey = pickle.load( open("serverPublicKey", "rb"))
        print >> sys.stderr, 'Public Key: ', self.serverPublicKey

        #TEST
        cipherText = self.serverPublicKey.encrypt('client1Password',32)

        print >> sys.stderr,'Cipher Text: ', cipherText

        #Server Info
        server_address = ('localhost', 10000)
        print >> sys.stderr, 'Connecting to %s port %s' % server_address


        #Data Serialization pickle
        #data = pickle.dumps(cipherText, -1)

        data = pickle.dumps(cipherText)

        #Authentication
        #key = str.encode(self.serverPublicKey)
        #iv = 0
        #cipher = DES3.new(key,blockalgo.MODE_ECB,iv)
        #cipherText = cipher.encrypt(self.clientPassword[0])

        # Connect the socket to the port where the server is listening
        self.sock.connect(server_address)

        #Send Authentication
        #fileName = 'authen.file'
        #f = open(fileName,'rb')
        #load = f.read(1024)
        #while(load):
        #    self.sock.send(load)
        #    print >> sys.stderr, 'Data Sent: ', load
        #    load = f.read(1024)



        #Send Authen
        self.sock.send(data)

        print >> sys.stderr, 'Authentication sent to Server'
        #Waiting for ack
        temp = self.sock.recv(1024)
        print >> sys.stderr, "peer client addr received: ", temp
        peer_client_addr = json.loads(temp)
        #print >> sys.stderr,"peer client addre: ", peer_client_addr

        try:
            # Send command
            command = commands.START
            self.sock.send(command)

            # Send data
            #message = 'Connecting to Server' # session key
            #Send authentication


            print >> sys.stderr, 'sending "%s"' % message
            self.sock.sendall(message)

            #Look for the response
            amount_received = 0
            amount_expected = len(message)
            receiver = ''
            while amount_received < amount_expected:
                data = self.sock.recv(16)
                receiver += data
                amount_received += len(data)

            print >> sys.stderr, 'received "%s"' % data

        finally:
            print >> sys.stderr, 'closing socket'
            self.sock.close()

    def comparePWD(self):
        password = self.e1.get()
        passwordHash = SHA256.new(password).digest()
        self.master.quit()
        print >> sys.stderr, 'Comparing Password'

        if passwordHash == self.passwordHash:
            print >> sys.stderr, 'User Authenticated'
            self.start()
        else:
            sys.exit("Password Error")

#    def authentication(self):


client = Client()