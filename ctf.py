import ssl
import json
import socket
from hashlib import sha1
from functools import reduce
from socketserver import BaseRequestHandler
from tlsserver import ThreadingTLSServer
import protocolmessages as pm
from pprint import pprint
from threading import Thread, RLock, Condition


class CTF(object):
    def __init__(self, options, cla_location=('localhost', 12348)):
        self.voter_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
            cafile="auth/ca-cert.pem")
        self.voter_context.load_cert_chain("auth/ctf-cert.pem",
            keyfile="auth/ctf-key.pem")
        self.voter_context.verify_mode = ssl.CERT_NONE

        self.cla_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
            cafile="auth/ca-cert.pem")
        self.cla_context.load_cert_chain("auth/ctf-cert.pem",
            keyfile="auth/ctf-key.pem")
        self.cla_context.verify_mode = ssl.CERT_REQUIRED
        self.cla_location = cla_location

        self.options = options
        for office in self.options['offices']:
            for candidatedict in office['candidates']:
                hashfunc = sha1()
                for key, value in candidatedict.items():
                    hashfunc.update(key.encode() + value.encode())
                candidatedict['sha1'] = hashfunc.hexdigest()

        self.optionsbytes = json.dumps(self.options).encode('utf-8')
        self.is_accepting_votes = False
        self.unused_validation_numbers = None
        self.is_finished = False
        self.lock = RLock()
        for office in self.options['offices']:
            for candidate in office['candidates']:
                candidate['votes'] = []
        self.options['office_indexes'] = {}
        for i, office in enumerate(self.options['offices']):
            self.options['office_indexes'][office['name']] = i
            office['candidate_hash_indexes'] = {}
            for j, candidate in enumerate(office['candidates']):
                office['candidate_hash_indexes'][candidate['sha1']] = j

    def ballot_is_valid(self, ballot):
        is_valid = False
        for ballot_office in ballot['offices']:
            if ballot_office['name'] in self.options['office_indexes'].keys():
                office_index = self.options['office_indexes'][ballot_office['name']]
                office_candidate_hashes = self.options['offices'][office_index]['candidate_hash_indexes'].keys()
                if ballot_office['candidate_hash'] in office_candidate_hashes:
                    is_valid = True
            else:
                return False
        return is_valid

    def count_vote(self, voter_random_id, validation_num, ballot):
        response = None
        if self.ballot_is_valid(ballot):
            with self.lock:
                if validation_num in self.unused_validation_numbers:
                    self.unused_validation_numbers.remove(validation_num)
                    for ballot_office in ballot['offices']:
                        office_index = self.options['office_indexes'][ballot_office['name']]
                        office = self.options['offices'][office_index]
                        candidate_index = office['candidate_hash_indexes'][ballot_office['candidate_hash']]
                        candidate = office['candidates'][candidate_index]
                        assert candidate['sha1'] == ballot_office['candidate_hash'], "Wrong candidate matched"
                        candidate['votes'].append(voter_random_id)
                        response = pm.VOTE_SUCCESS
                else:
                    response = pm.INVALID_VALIDATION_NUM
        else:
            response = pm.INVALID_BALLOT
        return response

    def output_results(self):
        try:
            sock = socket.create_connection(self.cla_location)
            sock = self.cla_context.wrap_socket(sock, server_hostname='CLA')
            with self.lock:
                vnumbytes = map(lambda x: x.to_bytes(8, 'big'), self.unused_validation_numbers)
                vnumlistbytes = reduce(lambda x, y: x + y, vnumbytes, b'')
                vnumcountbytes = len(self.unused_validation_numbers).to_bytes(4, 'big') 
            sock.sendall(pm.VNUM_REMAINDERS + vnumcountbytes + vnumlistbytes)
            resp = sock.recv(1)
            if resp == pm.VNUM_REMAIN_ACCEPT:
                print("CLA accepted unused vnums. Now printing election results")
            else:
                print("CLA response: {0}".format(resp))
            sock.close()
        except:
            print("could not establish communication with cla")
        print("saving election results to 'results.json'")
        with open('results.json', 'w') as fp:
            json.dump(self.options, fp)

    def voting_is_finished(self):
        self.is_finished = False
        if ctf.lock.acquire(blocking=False):
            if len(ctf.unused_validation_numbers) == 0:
                self.is_finished = True
            ctf.lock.release()
        return self.is_finished

    def force_finish_voting(self):
        with ctf.lock:
            ctf.is_finished = True
            print('voting finished by force')
            self.output_results()


class CTFCLARequestHandler(BaseRequestHandler):
    ctf = None
    def setup(self):
        print("serving", self.client_address)

    def handle(self):
        clacert = dict((x[0] for x in self.request.getpeercert()['subject']))
        if clacert['commonName'] == 'CLA':
            msg = self.request.recv(1)
            if msg == pm.VALIDATION_NUM_LIST:
                validation_num_count = int.from_bytes(self.request.recv(4), 'big')
                ctf.unused_validation_numbers = set()
                for x in range(validation_num_count):
                    ctf.unused_validation_numbers.add(int.from_bytes(self.request.recv(8), 'big'))
                ctf.is_accepting_votes = True
                self.request.sendall(pm.VNUM_LIST_ACCEPT)
            else:
                self.request.sendall(pm.UNKNOWN_MSG)

    def finish(self):
        print('done serving', self.client_address)
    


class CTFVoterRequestHandler(BaseRequestHandler):
    ctf = None
    def setup(self):
        print("serving {0} with {1}".format(self.client_address, self.request.cipher()))

    def handle(self):
        if ctf.is_accepting_votes:
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
                responsecode = ctf.count_vote(voter_id, validation_num, ballot)
                if responsecode is not None:
                    self.request.sendall(responsecode)
                else:
                    self.request.sendall(pm.VOTE_ERROR)
            else:
                self.request.sendall(pm.UNKNOWN_MSG)

    def finish(self):
        print('done serving', self.client_address)
        print("results so far:")
        pprint(ctf.options)
        if ctf.voting_is_finished():
            print('voting is finished')
            ctf.output_results()


def acceptclarequests(ctf, ctfserver):
    while not ctf.is_accepting_votes:
        ctfserver.handle_request()


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

    ctf = CTF(options)
    CTFVoterRequestHandler.ctf = ctf

    #vote = {
    #    'offices': [
    #        {
    #            'name': 'POTUS',
    #            'candidate_hash': <sha1 hash>,
    #        }
    #    ]
    #}

    ctfclaserver = ThreadingTLSServer(('localhost', 12347), CTFCLARequestHandler, sslcontext=ctf.cla_context)
    ctfclaserver.timeout = 1
    #acceptclarequests(ctf, ctfclaserver)
    Thread(target=acceptclarequests, args=(ctf, ctfclaserver)).start()

    ctfvoterserver = ThreadingTLSServer(('localhost', 12346), CTFVoterRequestHandler, sslcontext=ctf.voter_context)
    ctfvoterserver.timeout = 1
    try:
        while not ctf.is_finished:
            ctfvoterserver.handle_request()
    except KeyboardInterrupt:
        print("manually ending voting")
        ctf.force_finish_voting()

