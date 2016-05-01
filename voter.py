import ssl
import socket
import protocolmessages as pm
#from OpenSSL import crypto


class Voter(object):
    def __init__(self, certfile, keyfile, cafile='certs/ca-cert.pem',
            clalocation=('localhost', 12345), ctflocation=('localhost', 12346)):
        #with open(cafile) as cafp:
        #    self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cafp.buffer.read())
        #with open(certfile) as certfp:
        #    self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, certfp.buffer.read())
        #with open(keyfile) as keyfp:
        #    self.private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, keyfp.buffer.read())
        self.context = ssl.create_default_context(cafile=cafile)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.clalocation = clalocation
        self.ctflocation = ctflocation
    
    def connect_to_CLA(self):
        sock = socket.create_connection(self.clalocation)
        sock = self.context.wrap_socket(sock, server_hostname='CLA')
        return sock

    def request_validation_number(self):
        clasock = self.connect_to_CLA()
        clasock.sendall(pm.REQ_VALIDATION_NUM)
        msg = clasock.recv(1)
        if msg == pm.VALIDATION_NUM:
            vbytes = clasock.recv(8)
            self.validation_number = int.from_bytes(vbytes, 'big')
            print("got validation number: {0}".format(self.validation_number))
        else:
            print("get response: {0}".format(msg))



voter = Voter(certfile='test-cert.pem', keyfile='test-key.pem')
voter.request_validation_number()
