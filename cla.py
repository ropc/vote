import ssl
import socket
from socketserver import BaseRequestHandler
import concurrent.futures
from random import SystemRandom
from tlsserver import TLSServer, ThreadingTLSServer
from pprint import pprint
from functools import reduce
from threading import Thread, Lock
import protocolmessages as pm


class CLA(object):
    def __init__(self, voter_file,
            ctflocation=('localhost', 12347)):
        registered_voters = []
        with open(voter_file) as fp:
            for line in fp:
                registered_voters.append(line.rstrip())
        self.is_accepting_votes = False
        self.is_finished = False
        self.got_vnum_remainders = False
        self.registered_voters_numbers = {}
        self.validation_numbers = []
        self.unused_validation_numbers = set()
        for voter in registered_voters:
            self.registered_voters_numbers[voter] = None
            self.validation_numbers.append(SystemRandom().getrandbits(64))
        self.ctflocation = ctflocation
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
            cafile="auth/ca-cert.pem")
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_cert_chain("auth/cla-cert.pem",
            keyfile="auth/cla-key.pem")
    
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
        if resp == pm.VNUM_LIST_ACCEPT:
            print("ctf accepted list. now accepting vnum requests")
            self.is_accepting_votes = True
        else:
            print("ctf response: {0}".format(resp))
        sock.close()
    


class CLARequestHandler(BaseRequestHandler):
    cla = None
    def setup(self):
        print("serving", self.client_address)

    def handle(self):
        msg = self.request.recv(1)
        if cla.is_accepting_votes:
            if msg == pm.REQ_VALIDATION_NUM:
                print("got REQ_VALIDATION_NUM from")
                pprint(self.request.getpeercert())
                # this is just to get the certificate into a
                # dict that is actually useful
                votercert = dict((x[0] for x in self.request.getpeercert()['subject']))
                pprint(votercert)
                pprint(cla.registered_voters_numbers.keys())
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

class CLACTFRequestHandler(BaseRequestHandler):
    cla = None
    def setup(self):
        print("serving", self.client_address)

    def handle(self):
        ctfcert = dict((x[0] for x in self.request.getpeercert()['subject']))
        if ctfcert['commonName'] == 'CTF':
            msg = self.request.recv(1)
            if msg == pm.VNUM_REMAINDERS:
                validation_num_count = int.from_bytes(self.request.recv(4), 'big')
                for x in range(validation_num_count):
                    cla.unused_validation_numbers.add(int.from_bytes(self.request.recv(8), 'big'))
                cla.got_vnum_remainders = True 
                self.request.sendall(pm.VNUM_REMAIN_ACCEPT)
                cla.is_finished = True
            else:
                self.request.sendall(pm.UNKNOWN_MSG)
            #print('unused validation numbers: ({0} total)\n{1}'.format(
            #    len(cla.unused_validation_numbers), cla.unused_validation_numbers))
            if len(cla.unused_validation_numbers) > 0:
                print('voters who did not vote:')
                for voter, vnum in cla.registered_voters_numbers.items():
                    if ((vnum is not None and vnum in cla.unused_validation_numbers)
                            or vnum is None):
                        print(voter)

def acceptCTFvnums(cla, claserver):
    while not cla.got_vnum_remainders:
        claserver.handle_request()
   # Compare list values here?


# for reference:
# use randint = random.SystemRandom().getrandbits(64) to get a
# 64-bit random int, then do randint.to_bytes(64, 'big') to get a
# bytes object for this integer (big-endian encoded), and transfer
# this over the socket. to get the number back, use int.from_bytes(bytes)
# bytes represents an immutable byte array.

if __name__ == '__main__':
    cla = CLA('reg_voters.txt')
    cla.is_accepting_votes = True
    CLARequestHandler.cla = cla
    CLACTFRequestHandler.cla = cla

    cla.send_validation_numbers()

    clactfserver = ThreadingTLSServer(('localhost', 12348), CLACTFRequestHandler, sslcontext=cla.context)
    clactfserver.timeout = 1
    Thread(target=acceptCTFvnums, args=(cla, clactfserver)).start()

    tlsserver = ThreadingTLSServer(('localhost', 12345), CLARequestHandler, sslcontext=cla.context)
    tlsserver.timeout = 1
    while not cla.is_finished:
        tlsserver.handle_request()
