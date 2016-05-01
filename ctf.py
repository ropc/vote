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
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
            cafile="certs/ca-cert.pem")
        self.context.verify_mode = ssl.CERT_NONE
        self.context.load_cert_chain("certs/ctf-cert.pem",
            keyfile="certs/ctf-key.pem")
        self.options = options
        self.optionsbytes = json.dumps(self.options).encode('utf-8')


class CTFRequestHandler(BaseRequestHandler):
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
            ballot = self.request.recv(ballot_size)
            pprint(ballot)

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
    CTFRequestHandler.ctf = ctf

    #vote = {
    #    'offices': [
    #        {
    #            'name': 'POTUS',
    #            'candidate': <sha1 hash>,
    #        }
    #    ]
    #}

    ctfserver = ThreadingTLSServer(('localhost', 12346), CTFRequestHandler, sslcontext=ctf.context)
    ctfserver.serve_forever()