import ssl
import socket
import concurrent.futures


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
