import ssl
import socket
from socketserver import BaseRequestHandler
import concurrent.futures
from random import SystemRandom
from tlsserver import TLSServer, ThreadingTLSServer
from pprint import pprint
import protocolmessages as pm


class CLA(object):
    def __init__(self, registered_voters=['testdude']):
        self.is_accepting_votes = False
        self.voter_validation_number = {}
        self.registered_voters = set(registered_voters)
        self.validation_numbers = []
        for voter in registered_voters:
            self.voter_validation_number[voter] = None
            self.validation_numbers.append(SystemRandom().getrandbits(64))
    
    def get_validation_number(self, voter):
        if not self.is_accepting_votes or voter not in self.registered_voters:
            return None
        if self.voter_validation_number.get(voter) is None:
            random_index = SystemRandom().randint(0, len(self.validation_numbers) - 1)
            self.voter_validation_number[voter] = self.validation_numbers.pop(random_index)
        return self.voter_validation_number[voter]


class CLARequestHandler(BaseRequestHandler):
    cla = None
    def setup(self):
        print("serving", self.client_address)

    def handle(self):
        msg = self.request.recv(1)
        if msg == pm.REQ_VALIDATION_NUM:
            print("got REQ_VALIDATION_NUM from")
            pprint(self.request.getpeercert())
            # this is just to get the certificate into a
            # dict that is actually useful
            votercert = dict((x[0] for x in self.request.getpeercert()['subject']))
            vnum = cla.get_validation_number(votercert['commonName'])
            if vnum is not None:
                print("sending voter validation number: {0}".format(vnum))
                self.request.sendall(pm.VALIDATION_NUM + vnum.to_bytes(8, 'big'))
            else:
                print("sending UNREGISTERED_VOTER to {0}".format(self.client_address))
                self.request.sendall(pm.UNREGISTERED_VOTER)
        else:
            print("got unknown request:", msg)
            self.BaseRequestHandler.sendall(pm.UNKNOWN_MSG)

    def finish(self):
        print('done serving', self.client_address)



# for reference:
# use randint = random.SystemRandom().getrandbits(64) to get a
# 64-bit random int, then do randint.to_bytes(64, 'big') to get a
# bytes object for this integer (big-endian encoded), and transfer
# this over the socket. to get the number back, use int.from_bytes(bytes)
# bytes represents an immutable byte array.

if __name__ == '__main__':
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
        cafile="certs/ca-cert.pem")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(certfile="certs/cla-cert.pem", keyfile="certs/cla-key.pem")

    cla = CLA()
    cla.is_accepting_votes = True
    CLARequestHandler.cla = cla

    tlsserver = ThreadingTLSServer(('localhost', 12345), CLARequestHandler, sslcontext=ctx)
    tlsserver.serve_forever()
