import socket
import threading
import hashlib

import rsa

from client_common import cert_is_valid


class Client(object):
    def __init__(self):
        self.ca_addr = ('', 7070)

        # TODO: String IDs
        self.ID = 1

        # A key-pair generated using: rsa.generate_key_pair(1000037, 1000039)
        self.pub_key = (835209960655, 1000076001443)
        self.pvt_key = (656337451687, 1000076001443)

        self.ca_pub_key = (172946823661, 1000076001443)

        # Certificate that I will obtain from the CA
        self.certificate = ""

        # Key of the client that wants to talk to me
        # Will be obtained during key setup phase
        self.client_id = ""
        self.client_pub_key = ""

        # Socket on which I connect to a CA
        self.ca_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Socket on which other clients connect to me
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.client_sock.bind(('', 7171))

        try:
            self.ca_sock.connect(self.ca_addr)
        except OSError:
            print("> Could not connect to server. Ensure that it is running.")
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

        print("> I'm now listening on port: %d \n" %
              self.client_sock.getsockname()[1])

        self.client_sock.listen(5)

        while True:
            client, address = self.client_sock.accept()
            client.settimeout(60)

            # Spawn off a new thread to serve a client
            threading.Thread(
                target=self.serve_client,
                args=(client, address)
            ).start()

    def serve_client(self, client, address):
        # print(">>> New client wants to chat:", address)

        while True:
            try:
                data = client.recv(4096)
                if data:
                    data = data.decode()

                    if data.startswith("CLIENT_KEY:"):
                        req = data.lstrip("CLIENT_KEY:")

                        print("\n=================================\n")

                        valid, self.client_id, self.client_pub_key = cert_is_valid(req, self.ca_pub_key)

                        if not valid:
                            raise socket.timeout

                        print("\n=================================\n")

                        # Send my own information to the client
                        response = "CLIENT_KEY:" + self.certificate

                    elif data.startswith("CLIENT_MSG:"):
                        req = data.lstrip("CLIENT_MSG:")

                        # TODO: Decrypt data with self.pvt_key
                        # TODO: Decrypt data with self.client_pub_key

                        print("Received msg from client:", req)

                        response = "CLIENT_MSG:" + "Hello, client " + str(self.client_id)
                    else:
                        response = "echo: " + data.decode()

                    client.send(response.encode())
                else:
                    raise socket.timeout()

            except socket.timeout:
                print()
                # print(">>> Client disconnected: ", address, "\n")
                client.close()
                return False

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
