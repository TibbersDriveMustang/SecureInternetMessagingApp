import socket
import sys

class Server:
    def __init__(self):
        #Create a TCP/IP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #Bind the socket to the port
        self.server_address = ('localhost', 10000)
        print >> sys.stderr, 'Starting up on %s port %s' % self.server_address
        self.socket.bind(self.server_address)

        #Listen for incoming connections
        self.socket.listen(1)

    def start(self):
        while True:
            #Wait for a connection
            print >> sys.stderr, 'Waiting for a connection'
            connection, client_address = self.socket.accept()
            try:
                print >> sys.stderr, 'Connection from ', client_address

                #Receive the data in small chunks and retransmit it
                while True:
                    data =connection.recv(16)
                    print >> sys.stderr, 'received "%s"' % data
                    if data:
                        print >> sys.stderr, 'Sending data back to the client'
                        connection.sendall(data)
                    else:
                        print >> sys.stderr, 'no more data from', client_address
                        break
            finally:
                #Clean up the connection
                connection.close()
server = Server()
server.start()
