import socket
import sys
from Crypto.Hash import SHA256
from Tkinter import *

#public key encryption
from Crypto.Cipher import  DES3
from Crypto.Cipher import blockalgo

import pickle
import json

from Crypto.Cipher import AES
import base64
import os

import time

class commands:
    START = '1'
    AUTHEN = '2'
    STOP = '3'

class Client:
    clientPasswordList = ['client1','client2']
    client_1_address = ('localhost', 10001)
    client_2_address = ('localhost', 10002)
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
        self.passwordHash1 = SHA256.new(self.clientPasswordList[0]).digest()
        self.passwordHash2 = SHA256.new(self.clientPasswordList[1]).digest()

        self.master.mainloop()


    def start(self):
        #Load Server Public Key
        self.serverPublicKey = pickle.load( open("serverPublicKey", "rb"))
        print >> sys.stderr, 'Public Key: ', self.serverPublicKey

        #Send Encrypted Client Password to Server
        cipherText = None
        try:
            if self.ID == 1:
                cipherText = self.serverPublicKey.encrypt(self.clientPasswordList[0],32)
            elif self.ID == 2:
                cipherText = self.serverPublicKey.encrypt(self.clientPasswordList[1], 32)
        except RuntimeError:
            print ("No Such User")

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
        peer_client_addr = json.loads(temp)
        print >> sys.stderr,"peer client address/port received: ", peer_client_addr[0], ':', peer_client_addr[1]

        #Get Session Key
        sessionKeySeed = self.sock.recv(1024)
        print >> sys.stderr, 'sessionkey received: ', sessionKeySeed

        self.sock.close()

        self.setED(sessionKeySeed)

        #Client 1 Actions
        if self.ID == 1:
            #Set Timestamp to peer
            timeStamp = int(time.time())
            print >> sys.stderr, 'TimeStamp: ', timeStamp
            encodedTS = self.EncodeAES(self.cipher, str(timeStamp))
            print >> sys.stderr, 'encodedMsg: ',encodedTS

            #Send Timestamp
            self.udpSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udpSock.bind(self.client_1_address)
            self.udpSock.sendto(encodedTS,self.client_2_address)
            print >> sys.stderr, 'Client_1 UDP timeStamp Sent: ', encodedTS
            #Wait for respond
            timeStamp_incr_encoded, addr = self.udpSock.recvfrom(1024)
            timeStamp_incr = self.DecodeAES(self.cipher, timeStamp_incr_encoded)
            print >> sys.stderr, 'Client_1 UDP timeStamp Received: ', timeStamp_incr


        #Client 2 Actions
        if self.ID == 2:
            self.udpSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udpSock.bind(self.client_2_address)
            timeStampEncoded, addr = self.udpSock.recvfrom(1024)
            print >> sys.stderr, 'Client_2 UDP TimeStampEncoded Received: ', timeStampEncoded
            timeStamp2 = self.DecodeAES(self.cipher,timeStampEncoded)
            print >> sys.stderr,'Client_2 receives timeStamp',timeStamp2
            #Increase timeStamp by 1
            tempNum = int(timeStamp2)
            tempNum += 1
            encodedTS = self.EncodeAES(self.cipher, str(tempNum))
            self.udpSock.sendto(encodedTS,self.client_1_address)
            print >> sys.stderr, 'Client_2 UDP timeStamp + 1 Sent: ', encodedTS


        #Setup Communication

#        try:
            # Send command
#            command = commands.START
#            self.sock.send(command)

            # Send data
            #message = 'Connecting to Server' # session key
            #Send authentication


#            print >> sys.stderr, 'sending "%s"' % message
#            self.sock.sendall(message)

            #Look for the response
#            amount_received = 0
#            amount_expected = len(message)
#            receiver = ''
#            while amount_received < amount_expected:
#                data = self.sock.recv(16)
#                receiver += data
#                amount_received += len(data)

#            print >> sys.stderr, 'received "%s"' % data

#        finally:
#            print >> sys.stderr, 'closing socket'
#            self.sock.close()

    def comparePWD(self):
        password = self.e1.get()
        self.master.destroy()
        passwordHash = SHA256.new(password).digest()
        print >> sys.stderr, 'Comparing Password'

        if passwordHash == self.passwordHash1:
            print >> sys.stderr, 'User1 Authenticated'
            self.ID = 1
            # Bind different IP/PORT
            self.sock.bind(('',10001))
            self.start()
        elif passwordHash == self.passwordHash2:
            print >> sys.stderr, 'User2 Authenticated'
            self.ID = 2
            # Bind different IP/PORT
            self.sock.bind(('', 10002))
            self.start()
        else:
            sys.exit("Password Error")

#    def authentication(self):
    def setED(self, sessionKey):
        BLOCK_SIZE = 16
        PADDING = '{'
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
        self.sessionKey = sessionKey
        self.EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
        self.DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
        self.cipher  = AES.new(self.sessionKey)
        encoded = self.EncodeAES(self.cipher,'password')
        print >> sys.stderr,'Encode: ', encoded, 'Secret: ', self.sessionKey
        decoded = self.DecodeAES(self.cipher,encoded)
        print >> sys.stderr,'Decode: ', decoded



client = Client()