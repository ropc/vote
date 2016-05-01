import ssl
import socket
import json
from random import SystemRandom
import protocolmessages as pm
from pprint import pprint
#from OpenSSL import crypto


class Voter(object):
    def __init__(self, certfile, keyfile, cafile='certs/ca-cert.pem',
            cla_location=('localhost', 12345), ctf_location=('localhost', 12346)):
        #with open(cafile) as cafp:
        #    self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cafp.buffer.read())
        #with open(certfile) as certfp:
        #    self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, certfp.buffer.read())
        #with open(keyfile) as keyfp:
        #    self.private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, keyfp.buffer.read())
        self.cla_context = ssl.create_default_context(cafile=cafile)
        self.cla_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.ctf_context = ssl.create_default_context(cafile=cafile)
        self.validation_number = None
        self.cla_location = cla_location
        self.ctf_location = ctf_location

    def request_validation_number(self):
        sock = socket.create_connection(self.cla_location)
        sock = self.cla_context.wrap_socket(sock, server_hostname='CLA')
        sock.sendall(pm.REQ_VALIDATION_NUM)
        msg = sock.recv(1)
        if msg == pm.VALIDATION_NUM:
            vbytes = sock.recv(8)
            self.validation_number = int.from_bytes(vbytes, 'big')
            print("got validation number: {0}".format(self.validation_number))
        else:
            print("get response: {0}".format(msg))
        sock.close()

    def get_ballot(self):
        sock = socket.create_connection(self.ctf_location)
        sock = self.ctf_context.wrap_socket(sock, server_hostname='CTF')
        sock.sendall(pm.VOTING_OPTIONS_REQUEST)
        msg = sock.recv(1)
        if msg == pm.VOTING_OPTIONS_RESPONSE:
            size = int.from_bytes(sock.recv(4), 'big')
            options = json.loads(str(sock.recv(size), 'utf-8'))
            pprint(options)


    #def vote(self, ballot):



if __name__ == '__main__':
    voter = Voter(certfile='test-cert.pem', keyfile='test-key.pem')
    #voter.request_validation_number()
    voter.get_ballot()


