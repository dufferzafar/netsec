import socket
import threading
import hashlib

import rsa

from client_common import cert_is_valid, get_certificate


class Client(object):
    def __init__(self):
        self.ca_addr = ('', 7070)

        self.ID = "Shadab"

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
        self.certificate = get_certificate(self.ca_sock, self.ID, self.pub_key, self.ca_pub_key)

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
                        req = data[len("CLIENT_KEY:"):]

                        print("\n=================================\n")

                        valid, self.client_id, self.client_pub_key = cert_is_valid(req, self.ca_pub_key)

                        if not valid:
                            raise socket.timeout

                        print("\n=================================\n")

                        # Send my own information to the client
                        response = "CLIENT_KEY:" + self.certificate

                    elif data.startswith("CLIENT_MSG:"):
                        msg = data[len("CLIENT_MSG:"):]

                        # Double decryption of hello message
                        msg = rsa.decrypt(msg, self.pvt_key)
                        msg = rsa.decrypt(msg, self.client_pub_key)

                        print("Received msg from client:", msg)

                        # Double encryption of hello message
                        msg = "Hello, " + str(self.client_id)
                        msg = rsa.encrypt(msg, self.pvt_key)
                        msg = rsa.encrypt(msg, self.client_pub_key)

                        response = "CLIENT_MSG:" + msg
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


if __name__ == '__main__':
    Client().run()
