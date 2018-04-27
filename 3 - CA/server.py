import threading
import socket
import datetime
import hashlib

import rsa


class CertificationAuthorityServer(object):
    def __init__(self):
        # A key-pair generated using: rsa.generate_key_pair(1000037, 1000039)
        self.pub_key = (172946823661, 1000076001443)
        self.pvt_key = (739559892397, 1000076001443)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', 7070))

    def run(self):
        print("> Certification authority now listening on port: %d \n" %
              self.sock.getsockname()[1])

        self.sock.listen(5)

        while True:
            client, address = self.sock.accept()
            client.settimeout(60)

            # Spawn off a new thread to serve a client
            threading.Thread(
                target=self.serve_client,
                args=(client, address)
            ).start()

    def serve_client(self, client, address):
        print(">>> New client connected:", address, "\n")

        while True:
            try:
                data = client.recv(4096)
                if data:

                    data = data.decode()
                    if data.startswith("REQ_CERT:"):
                        req = data[len("REQ_CERT:"):]

                        # TODO: Decrypt request with private key of CA

                        print("> Received request for new certificate: ", req)

                        # Time of issuing of certificate
                        now = str(datetime.datetime.utcnow())
                        req += "|" + now

                        print("> Time of issuing: ", now)

                        h = hashlib.sha256(req.encode()).hexdigest()
                        certi = rsa.encrypt(h, self.pvt_key)

                        print("> Certificate: ", certi)

                        # Also send the time back so client is able to verify the thing
                        response = req + "|" + certi
                    else:
                        response = "echo: " + data.decode()

                    client.send(response.encode())
                else:
                    raise socket.timeout()

            except socket.timeout:
                print()
                print(">>> Client disconnected: ", address, "\n")
                client.close()
                return False


if __name__ == "__main__":
    CertificationAuthorityServer().run()
