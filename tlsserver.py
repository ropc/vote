from ssl import create_default_context, Purpose, SSLError
from socketserver import TCPServer, ForkingMixIn, ThreadingMixIn


class TLSServer(TCPServer):
    def __init__(self, server_address, RequestHandlerClass,
        sslcontext=create_default_context(Purpose.CLIENT_AUTH), bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.sslcontext = sslcontext

    def get_request(self):
        request, client_address = self.socket.accept()
        request = self.sslcontext.wrap_socket(request,
            server_side=True, do_handshake_on_connect=False)
        return request, client_address

    def verify_request(self, request, client_address):
        try:
            request.do_handshake()
            return True
        except SSLError as e:
            print(e)
            return False
        except:
            return False

class ForkingTLSServer(ForkingMixIn, TLSServer):
    pass


class ThreadingTLSServer(ThreadingMixIn, TLSServer):
    pass
