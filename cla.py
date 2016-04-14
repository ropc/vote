import ssl
import socket
import concurrent.futures
from random import SystemRandom

class CLA(object):
    def __init__(self, voters=['testdude']):
        self.is_accepting_votes = False
        self.voter_validation_number = {}
        self.validation_numbers = []
        osrandom = SystemRandom()
        for voter in voters:
            self.voter_validation_number[voter] = None
            self.validation_numbers.append(osrandom.getrandbits(64))
    
    def get_validation_number(self, voter):
        if not is_accepting_votes:
            return None
        if self.voter_validation_number.get(voter) is None:
            random_index = SystemRandom().randint(0, len(self.validation_numbers) - 1)
            self.voter_validation_number[voter] = self.validation_numbers.pop(random_index)
        return self.voter_validation_number[voter]

# for reference:
# use randint = random.SystemRandom().getrandbits(64) to get a
# 64-bit random int, then do randint.to_bytes(64, 'big') to get a
# bytes object for this integer (big-endian encoded), and transfer
# this over the socket. to get the number back, use int.from_bytes(bytes)
# bytes represents an immutable byte array.



ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
    cafile="certs/ca-cert.pem")

ctx.load_cert_chain(certfile="certs/cla-cert.pem", keyfile="certs/cla-key.pem")

bindsocket = socket.socket()
bindsocket.bind(('localhost', 12346))
bindsocket.listen(5)


def processConnection(context, socket):
    connstream = context.wrap_socket(socket, server_side=True)
    try:
        connstream.send(b'hello')
        print(fromaddr, connstream)
    finally:
        connstream.shutdown(socket.SHUT_RDWR)
        connstream.close()

with concurrent.futures.ProcessPoolExecutor() as executor:
    newsocket, fromaddr = bindsocket.accept()
    executor.submit(processConnection, ctx, newsocket)
