import socket
import sys

from Crypto.Cipher import AES
from Crypto import Random
import base64
import os
from Crypto.PublicKey import RSA
from Crypto import Random
from OpenSSL import crypto, SSL
import pickle
import json

class commands:
    START = '1'
    AUTHEN = '2'
    STOP = '3'

class Server:
    #Place to store all clients hashed password
    publicKey = 'server_public_key'
    # clientID : clientPassword
    passwordList = ['client1','client2']
    # Store client IP Address
    client_1_address = ['localhost', 10001]
    client_2_address = ['localhost', 10002]
    sessionKeyClue = None

    def __init__(self):
        #Test
        #key = str.encode(self.publicKey)
        #print >> sys.stderr, key.exportKey('OpenSSH')

        #Generate Public/Private Key
        random_generator = Random.new().read
        self.key = RSA.generate(1024,random_generator)

        print >> sys.stderr, 'Key Pairs Generated : ', self.key

        #Wrtie public key to file
        pickle.dump(self.key.publickey(),open("serverPublicKey","wb"))

        #Create a TCP/IP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #Bind the socket to the port
        self.server_address = ('localhost', 10000)
        print >> sys.stderr, 'Starting up on %s port %s' % self.server_address
        self.socket.bind(self.server_address)

        #Listen for incoming connections
        self.socket.listen(1)
        self.start()

    def start(self):
        while True:
            #Wait for a connection
            print >> sys.stderr, 'Waiting for a connection'
            connection, client_address = self.socket.accept()
            try:
                print >> sys.stderr, 'Connection from ', client_address

                #Data receive pickle packet
                pickle_receiver = connection.recv(1024)

                authen = pickle.loads(pickle_receiver)

                plainAuthn = self.key.decrypt(authen)

                print >> sys.stderr, 'Received authen: ', authen, 'Decoded: ', plainAuthn

                #Client 1
                if plainAuthn == self.passwordList[0]:
                    print >> sys.stderr, "Client_1 Authen Successfully"
                    temp = json.dumps(self.client_2_address)
                    #send peer client address
                    connection.send(temp)
                    #Send Session Key
                    if self.sessionKeyClue == None:
                        self.sessionKeyClue = self.setSessionKeySeed()
                    connection.send(self.sessionKeyClue)
                    print >> sys.stderr, "Peer Address And SessionKey Sent to Client 1"

                #Client 2
                if plainAuthn == self.passwordList[1]:
                    print >> sys.stderr, "Client_2 Authen Successfully"
                    temp2 = json.dumps(self.client_1_address)
                    connection.send(temp2)
                    # Send Session Key
                    if self.sessionKeyClue == None:
                        self.sessionKeyClue = self.setSessionKeySeed()
                    connection.send(self.sessionKeyClue)
                    print >> sys.stderr, "Peer Address And SessionKey Sent to Client 2"

            finally:
                #Clean up the connection
                print >> sys.stderr, "Connection Close"
                connection.close()


    def setSessionKeySeed(self):
        BLOCK_SIZE = 16
        secret = os.urandom(BLOCK_SIZE)
        return secret

    def encryption(self,privateInfo, key):
        #32 bytes = 256 bits
        #16 = 128 bits
        #the block size for cipher obj, can be 16 24 or 32. 16 matches 128 bit.
        BLOCK_SIZE = 16
        PADDING = '{'
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        msg = iv + cipher.encrypt(key)

    def testEncryption(self):
        print >> sys.stderr, "TESTING"
        key = b'Sixteen byte key'
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        msg = iv + cipher.encrypt(b'Attack at dawn')
        print >> sys.stderr, 'Crypted Message: "%s"' % msg

server = Server()
