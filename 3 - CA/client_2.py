import socket
import rsa

from client_common import cert_is_valid, get_certificate


class Client(object):
    def __init__(self):
        self.ca_addr = ('', 7070)
        self.client_addr = ('', 7171)

        self.ID = "Nichit"

        # A key-pair generated using: rsa.generate_key_pair(1000037, 1000039)
        self.pub_key = (927326331365, 1000076001443)
        self.pvt_key = (765829640285, 1000076001443)

        self.ca_pub_key = (172946823661, 1000076001443)

        # Certificate that I will obtain from the CA
        self.certificate = ""

        # Key of the client that wants to talk to me
        # Will be obtained during key setup phase
        self.client_id = ""
        self.client_pub_key = ""

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
        self.certificate = get_certificate(self.ca_sock, self.ID, self.pub_key, self.ca_pub_key)

        # The certificate received is encrypted with the private key of the authority
        # so, it can be opened
        # now, certi = self.certificate.split("|")

        print("\nReceived certificate from CA.\n")
        print(self.certificate)

        print("\n===========================================================================================\n")

        print("> Now connecting to client on port: %d \n" %
              self.client_sock.getpeername()[1])

        print("> Sending my public key & certificate")

        req = "CLIENT_KEY:" + self.certificate
        self.client_sock.send(req.encode())

        #####################################################################

        # Client sends its key & certificate back

        resp = self.client_sock.recv(4096)
        resp = resp.decode()

        if resp.startswith("CLIENT_KEY:"):

            print("\n=================================\n")
            print("> Client has sent its public key & certificate: \n")

            req = resp[len("CLIENT_KEY:"):]

            valid, self.client_id, self.client_pub_key = cert_is_valid(req, self.ca_pub_key)

            if not valid:
                exit()

        else:
            print("\nUnexpected reply from client")
            exit()

        #####################################################################

        # Send hello msg to client
        print("\n=================================\n")

        # Double encryption of hello message
        msg = "Hello, " + str(self.client_id)
        msg = rsa.encrypt(msg, self.pvt_key)
        msg = rsa.encrypt(msg, self.client_pub_key)

        req = "CLIENT_MSG:" + msg
        self.client_sock.send(req.encode())

        #####################################################################

        resp = self.client_sock.recv(4096)
        resp = resp.decode()

        # Client has sent its key back
        if resp.startswith("CLIENT_MSG:"):
            msg = resp[len("CLIENT_MSG:"):]

            # # Double decryption of hello message
            msg = rsa.decrypt(msg, self.pvt_key)
            msg = rsa.decrypt(msg, self.client_pub_key)

            print("Received msg from client:", msg)
        else:
            print("\nUnexpected reply from client")
            exit()

        # print("Response from client:", resp)


if __name__ == '__main__':
    Client().run()
