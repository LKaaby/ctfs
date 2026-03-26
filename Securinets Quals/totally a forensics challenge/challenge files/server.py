from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
FLAG = "Securinets{y0u_th0ugh1_1t_w4s_f0rens1cs_but_1t_w4s_m3_crypto!!}"
class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        art = r"""
        #########################################################################
        #                                                                       #
        #   Well good job brother!                                              #
        #                                                                       #
        #      .--.   .--.                                                      #
        #     ( o_o) (o_o )                                                     #
        #      '--'   '--'                                                      #
        #                                                                       #
        #   FLAG: {}                                                  
        #                                                                       #
        #########################################################################
        """.format(FLAG)
        self.wfile.write(art.encode('utf-8'))

httpd = HTTPServer(('0.0.0.0', 4443), Handler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

# HARD LOCK TO TLS 1.2
context.options |= ssl.OP_NO_TLSv1_3
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_2

# Force RSA key exchange (no ECDHE)
context.set_ciphers("RSA")
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("HTTPS server running on port 4443…")
httpd.serve_forever()
