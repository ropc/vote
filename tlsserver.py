from ssl import create_default_context, Purpose, SSLError
from socketserver import TCPServer, ForkingMixIn, ThreadingMixIn


class TLSServer(TCPServer):
    """TLSServer implementation
    
    Provides TLS/SSL connections on top of a TCP connection
    using Python's ssl module.
    Note that the given RequestHandlerClass will receive an
    ssl.SSLSocket object (in self.request) instead of a regular
    socket object. These are described in:
    https://docs.python.org/3.4/library/ssl.html#ssl.SSLSocket
    
    Extends:
        TCPServer
    
    Instance variables:
        sslcontext {ssl.SSLContext} -- object to be used in all connections
                                        established by this server
    """

    def __init__(self, server_address, RequestHandlerClass,
        sslcontext=create_default_context(Purpose.CLIENT_AUTH), bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.sslcontext = sslcontext

    def get_request(self):
        request, client_address = super().get_request()
        request = self.sslcontext.wrap_socket(request,
            server_side=True, do_handshake_on_connect=False)
        return request, client_address

    def verify_request(self, request, client_address):
        try:
            # this requires some overhead,
            # may want to do this on a separate thread/process
            # maybe even just have an SSLRequestHnadler class
            # that takes care of the ssl context request wrapping
            request.do_handshake()
            return True
        except SSLError as e:
            print(e)
        return False


class ForkingTLSServer(ForkingMixIn, TLSServer): pass


class ThreadingTLSServer(ThreadingMixIn, TLSServer): pass
