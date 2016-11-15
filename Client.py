import socket
import sys
import Crypto


class Client:
    def __init__(self):
        #Create a TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #Connect the socket to the port where the server is listening
        server_address = ('localhost', 10000)
        print >> sys.stderr, 'Connecting to %s port %s' % server_address
        self.sock.connect(server_address)


    def start(self):
        try:
            #Send data
            message = 'This is the message. It will be repeated.'
            print >> sys.stderr, 'sending "%s"' % message
            self.sock.sendall(message)

            #Look for the response
            amount_received = 0
            amount_expected = len(message)

            while amount_received < amount_expected:
                data = self.sock.recv(16)
                amount_received += len(data)
                print >> sys.stderr, 'received "%s"' % data

        finally:
            print >> sys.stderr, 'closing socket'
            self.sock.close()

client = Client()
client.start()