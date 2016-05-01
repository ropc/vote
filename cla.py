import ssl
import socket
from socketserver import BaseRequestHandler
import concurrent.futures
from random import SystemRandom
from tlsserver import TLSServer, ThreadingTLSServer
from pprint import pprint
import protocolmessages as pm


class CLA(object):
    def __init__(self, registered_voters=['test'],
            ctflocation=('localhost', 12346)):
        self.is_accepting_votes = False
        self.registered_voters_numbers = {}
        self.validation_numbers = []
        for voter in registered_voters:
            self.registered_voters_numbers[voter] = None
            self.validation_numbers.append(SystemRandom().getrandbits(64))
        self.ctflocation = ctflocation
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
            cafile="certs/ca-cert.pem")
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_cert_chain(certfile="certs/cla-cert.pem",
            keyfile="certs/cla-key.pem")
    
    def get_validation_number(self, voter):
        """get the validation number for the given voter
        
        if the given voter has not yet been assigned a validation
        number, then one of the validation numbers is randomly
        selected for this user and stored as this user's validation
        number. THAT LIST OF VALIDATION NUMBERS AND THE STORING FOR
        THE VOTER'S VALIDATION NUMBER NEEDS TO EITHER HAVE A LOCK
        OR BE ENSURED THAT IT IS ONLY EXECUTED BY ONE DISTRIBUTOR
        THREAD
        
        Arguments:
            voter {string} -- the voter's commonName. this may be
                                changed to the voter's whole certificate
        
        Returns:
            int/None -- int representing the validation number if
                        successful, None otherwise.
        """ 
        if not self.is_accepting_votes or voter not in self.registered_voters_numbers.keys():
            return None
        if self.registered_voters_numbers.get(voter) is None:
            random_index = SystemRandom().randint(0, len(self.validation_numbers) - 1)
            self.registered_voters_numbers[voter] = self.validation_numbers.pop(random_index)
        return self.registered_voters_numbers[voter]

    def send_validation_numbers(self):
        sock = socket.create_connection(self.ctflocation)
        sock = self.context.wrap_socket(sock, server_hostname='CTF')
        vnumbytes = map(lambda x: x.to_bytes(8, 'big'), self.validation_numbers)
        vnumlistbytes = reduce(lambda x, y: x + y, vnumbytes)
        vnumcountbytes = len(self.validation_numbers).to_bytes(4, 'big')
        sock.sendall(pm.VALIDATION_NUM_LIST + vnumcountbytes + vnumlistbytes)
        resp = sock.recv(1)
        if resp != pm.VNUM_LIST_ACCEPT:
            print("ctf accepted list. now accepting vnum requests")
            self.is_accepting_votes = True
        else:
            print("ctf response: {0}".format(resp))


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
    cla = CLA()
    cla.is_accepting_votes = True
    CLARequestHandler.cla = cla

    tlsserver = ThreadingTLSServer(('localhost', 12345), CLARequestHandler, sslcontext=cla.context)
    tlsserver.serve_forever()
