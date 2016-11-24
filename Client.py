import socket
import sys
import Crypto
from Tkinter import *

class commands:
    START = '1'
    AUTHEN = '2'
    STOP = '3'

class Client:
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

        #Connect the socket to the port where the server is listening
        server_address = ('localhost', 10000)
        print >> sys.stderr, 'Connecting to %s port %s' % server_address
        self.sock.connect(server_address)

        mainloop()

    def start(self):
        try:
            # Send command
            command = commands.START
            self.sock.send(command)

            # Send data
            message = 'Client Password: ' + self.password
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

    def comparePWD(self):
        self.password = self.e1.get()
        print >> sys.stderr, self.password
        self.master.quit()
        print >> sys.stderr, 'Compare Password'


#    def authentication(self):


client = Client()
client.start()