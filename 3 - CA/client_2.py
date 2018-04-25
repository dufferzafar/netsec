import socket


class Client(object):
    def __init__(self):
        self.ca_addr = ('', 7070)
        self.client_addr = ('', 7171)

        # TODO: String IDs
        self.ID = 2

        # A key-pair generated using: rsa.generate_key_pair(1000003, 1000033)
        self.pub_key = (172946823661, 1000072001287)
        self.pvt_key = (613431099685, 1000072001287)

        self.ca_pub_key = (172946823661, 1000076001443)

        # Certificate that I will obtain from the CA
        self.certificate = ""

        # Socket on which I connect to a CA
        self.ca_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Socket on which I connect to other client
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.ca_sock.connect(self.ca_addr)
        except OSError:
            print("> Could not connect to server. Ensure that it is running.")
            exit(1)

        try:
            self.client_sock.connect(self.client_addr)
        except OSError:
            print("> Could not connect to client 1. Ensure that it is running.")
            exit(1)

    def run(self):

        # TODO: Only get it if not already present?
        self.certificate = self.get_certificate()

        # The certificate received is encrypted with the private key of the authority
        # so, it can be opened
        # now, certi = self.certificate.split("|")

        print("\nReceived certificate from CA.\n")
        print(self.certificate)

        print("\n===========================================================================================\n")

        print("> Now connecting to client on port: %d \n" %
              self.client_sock.getpeername()[1])

        print("> Sending my public key & certificate")

        req = "CLIENT_HELLO:" + self.certificate
        self.client_sock.send(req.encode())

        resp = self.client_sock.recv(4096)
        resp = resp.decode()

        print("Response from client:", resp)

    def get_certificate(self):

        print("My ID: ", self.ID)
        print("My Public Key: ", self.pub_key)

        print("\nSending request for a new certificate to CA")

        # TODO: Encrypt request with public key of CA
        req = "REQ_CERT:%d|%d|%d" % (self.ID, *self.pub_key)
        self.ca_sock.send(req.encode())

        resp = self.ca_sock.recv(4096)
        resp = resp.decode()

        self.ca_sock.close()

        return resp


if __name__ == '__main__':
    Client().run()
