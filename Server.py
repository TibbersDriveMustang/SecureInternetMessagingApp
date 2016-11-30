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

class commands:
    START = '1'
    AUTHEN = '2'
    STOP = '3'

class Server:
    #Place to store all clients hashed password
    publicKey = 'server_public_key'
    # clientID : clientPassword
    passwordList = {'1' : '11', '2' : '12'}
    # Store client IP Address
    clientAddressList = {}

    def __init__(self):
        #Test
        #key = str.encode(self.publicKey)
        #print >> sys.stderr, key.exportKey('OpenSSH')

        #Generate Public/Private Key
        random_generator = Random.new().read
        key = RSA.generate(1024,random_generator)

        print >> sys.stderr, 'Key Pairs Generated : ', key

        #Wrtie public key to file
        pickle.dump(key.publickey(),open("serverPublicKey","wb"))

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

                #Receive the data in small chunks and retransmit it
                clientAuthn = connection.recv(16)
                key = str.encode(self.publicKey)

                #Receiving commands
                command = connection.recv(16)
                if(command == commands.START):
                    print >> sys.stderr, 'Starting'

                info = ''
                while True:
                    receiver = connection.recv(16)
                    if receiver:
                        info += receiver
                        print >> sys.stderr, 'received "%s"' % info

                        #Send acknowledge back to clinet
                        acknowledge = 'Password Received'
                        connection.sendall(acknowledge)
                    else:
                        self.testEncryption()
                        print >> sys.stderr, 'no more data from', client_address
                        break

            finally:
                #Clean up the connection
                print >> sys.stderr, "Connection Close"
                connection.close()

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
