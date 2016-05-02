import ssl
import socket
import json
from random import SystemRandom
import protocolmessages as pm
from pprint import pprint
import argparse
#from OpenSSL import crypto


class Voter(object):
    def __init__(self, certfile, keyfile, cafile='auth/ca-cert.pem',
            cla_location=('localhost', 12345), ctf_location=('localhost', 12346)):
        #with open(cafile) as cafp:
        #    self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cafp.buffer.read())
        #with open(certfile) as certfp:
        #    self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, certfp.buffer.read())
        #with open(keyfile) as keyfp:
        #    self.private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, keyfp.buffer.read())
        print(certfile, keyfile)
        self.cla_context = ssl.create_default_context(cafile=cafile)
        self.cla_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.ctf_context = ssl.create_default_context(cafile=cafile)
        self.random_voter_id = SystemRandom().getrandbits(64)
        self.validation_number = None
        self.cla_location = cla_location
        self.ctf_location = ctf_location

    def request_validation_number(self):
        is_successful = False
        sock = socket.create_connection(self.cla_location)
        sock = self.cla_context.wrap_socket(sock, server_hostname='CLA')
        sock.sendall(pm.REQ_VALIDATION_NUM)
        msg = sock.recv(1)
        if msg == pm.VALIDATION_NUM:
            vbytes = sock.recv(8)
            self.validation_number = int.from_bytes(vbytes, 'big')
            print("got validation number: {0}".format(self.validation_number))
            is_successful = True
        elif msg == pm.UNREGISTERED_VOTER:
            print("voter unregistered")
        else:
            print("get response: {0}".format(msg))
        sock.close()
        return is_successful

    def get_options(self):
        sock = socket.create_connection(self.ctf_location)
        sock = self.ctf_context.wrap_socket(sock, server_hostname='CTF')
        sock.sendall(pm.VOTING_OPTIONS_REQUEST)
        msg = sock.recv(1)
        if msg == pm.VOTING_OPTIONS_RESPONSE:
            size = int.from_bytes(sock.recv(4), 'big')
            options = json.loads(str(sock.recv(size), 'utf-8'))
        sock.close()
        return options

    def vote(self, ballot):
        sock = socket.create_connection(self.ctf_location)
        sock = self.ctf_context.wrap_socket(sock, server_hostname='CTF')
        ballotbytes = json.dumps(ballot).encode('utf-8')
        sock.sendall(pm.VOTE
                        + self.random_voter_id.to_bytes(8, 'big')
                        + self.validation_number.to_bytes(8, 'big')
                        + len(ballotbytes).to_bytes(4, 'big')
                        + ballotbytes)
        print('sent in ballot:\n{0}\nwith random voter id: {1}'.format(ballot,
                                                            self.random_voter_id))
        msg = sock.recv(1)
        if msg == pm.VOTE_SUCCESS:
            print("vote was successful")
        elif msg == pm.INVALID_BALLOT:
            print("vote was rejected: ballot was in incorrect format")
        elif msg == pm.INVALID_VALIDATION_NUM:
            print("vote was rejected: invalid validation number")
        else:
            print('ctf responds: {0}'.format(msg))
        sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--certfile', metavar='CERTFILE', nargs=1,
                        default='test-cert.pem', dest='certfile', type=str)
    parser.add_argument('-k', '--keyfile', metavar='KEYFILE', nargs=1,
                        default='test-key.pem', dest='keyfile', type=str)
    args = parser.parse_args()

    voter = Voter(certfile=args.certfile[0], keyfile=args.keyfile[0])
    if voter.request_validation_number():
        options = voter.get_options()
        pprint(options)

        ballot = {'offices': []}

        for office in options['offices']:
            print("For {0}:".format(office['name']))
            for i, candidate in enumerate(office['candidates']):
                info = 'option {0}: '.format(i)
                for key, value in candidate.items():
                    if key != 'sha1':
                        info += '{0}: {1}, '.format(key, value)
                print(info)
            index = int(input(""))

            candidate_hash = office['candidates'][index]['sha1']

            ballot['offices'].append({
                    'name': office['name'],
                    'candidate_hash': candidate_hash,
                })

        voter.vote(ballot)




