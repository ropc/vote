import ssl
from socketserver import TCPServer


class TLSServer(TCPServer):
    def __init__(self, server_address, RequestHandlerClass,
        sslcontext=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH), bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.sslcontext = sslcontext

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        newsocket = self.sslcontext.wrap_socket(newsocket,
            server_side=True, do_handshake_on_connect=False)
        return newsocket, fromaddr

    def verify_request(self, request, client_address):
        try:
            request.do_handshake()
            return True
        except ssl.SSLError as e:
            print(e)
            return False
        except:
            return False
