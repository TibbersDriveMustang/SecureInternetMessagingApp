import socket
import sys

from Crypto.Cipher import AES
from Crypto import Random
import base64
import os

class Server:
    #Place to store all clients hashed password
    passwordList = {}

    def __init__(self):
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
                while True:
                    data = connection.recv(16)
                    print >> sys.stderr, 'received "%s"' % data
                    if data:
                        print >> sys.stderr, 'Sending data back to the client'
                        connection.sendall(data)
                    else:
                        self.testEncryption()
                        print >> sys.stderr, 'no more data from', client_address
                        break
            finally:
                #Clean up the connection
                print >> sys.stderr, "Connection Close"
                connection.close()

    def encryption(self,privateInfo):
        #32 bytes = 256 bits
        #16 = 128 bits
        #the block size for cipher obj, can be 16 24 or 32. 16 matches 128 bit.
        BLOCK_SIZE = 16
        PADDING = '{'
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

    def testEncryption(self):
        key = b'Sixteen byte key'
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        msg = iv + cipher.encrypt(b'Attack at dawn')
        print >> sys.stderr, 'Crypted Message: "%s"' % msg

server = Server()
