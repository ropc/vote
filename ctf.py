import ssl
import json
from hashlib import sha1
from functools import reduce
from socketserver import BaseRequestHandler
from tlsserver import ThreadingTLSServer
import protocolmessages as pm
from pprint import pprint


class CTF(object):
    def __init__(self, options, clalocation=('localhost', 12345)):
        self.voter_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
            cafile="auth/ca-cert.pem")
        self.voter_context.verify_mode = ssl.CERT_NONE
        self.voter_context.load_cert_chain("auth/ctf-cert.pem",
            keyfile="auth/ctf-key.pem")
        self.cla_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
            cafile="auth/ca-cert.pem")
        self.cla_context.verify_mode = ssl.CERT_REQUIRED
        self.cla_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
            cafile="auth/ca-cert.pem")

        self.options = options
        self.optionsbytes = json.dumps(self.options).encode('utf-8')
        self.is_accepting_votes = False
        self.validation_numbers = None


class CTFCLARequestHandler(BaseRequestHandler):
    def handle(self):
        cert = self.request.getpeercert()
        print(cert)
        #msg = self.request.recv(1)
        #if msg == pm.VALIDATION_NUM_LIST:




class CTFVoterRequestHandler(BaseRequestHandler):
    ctf = None
    def setup(self):
        print("serving", self.client_address)

    def handle(self):
        msg = self.request.recv(1)
        if msg == pm.VOTING_OPTIONS_REQUEST:
            self.request.sendall(pm.VOTING_OPTIONS_RESPONSE
                                    + len(ctf.optionsbytes).to_bytes(4, 'big')
                                    + ctf.optionsbytes)
        elif msg == pm.VOTE:
            voter_id = int.from_bytes(self.request.recv(8), 'big')
            validation_num = int.from_bytes(self.request.recv(8), 'big')
            ballot_size = int.from_bytes(self.request.recv(4), 'big')
            ballot = json.loads(str(self.request.recv(ballot_size), 'utf-8'))
            pprint(ballot)
        else:
            self.request.sendall(pm.UNKNOWN_MSG)

    def finish(self):
        print('done serving', self.client_address)


if __name__ == '__main__':

    options = {
        'offices' : [
            {
                'name': 'POTUS',
                'candidates': [
                    {
                        'name': 'Trump',
                        'party': 'Republican',
                    },
                    {
                        'name': 'Hillary',
                        'party': 'Democrat',
                    },
                ]
            }
        ]
    }

    for office in options['offices']:
        for candidatedict in office['candidates']:
            hashfunc = sha1()
            for key, value in candidatedict.items():
                hashfunc.update(key.encode() + value.encode())
            candidatedict['sha1'] = hashfunc.hexdigest()

    ctf = CTF(options)
    CTFVoterRequestHandler.ctf = ctf

    #vote = {
    #    'offices': [
    #        {
    #            'name': 'POTUS',
    #            'candidate': <sha1 hash>,
    #        }
    #    ]
    #}

    ctfserver = ThreadingTLSServer(('localhost', 12346), CTFCLARequestHandler, sslcontext=ctf.cla_context)
    while not ctf.is_accepting_votes:
        ctfserver.handle_request()
    ctfserver = ThreadingTLSServer(('localhost', 12346), CTFVoterRequestHandler, sslcontext=ctf.voter_context)
    ctfserver.serve_forever()
