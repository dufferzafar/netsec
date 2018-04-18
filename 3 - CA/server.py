import threading
import socket

# A certificate:
# CERTA = ENC_PR_X (ID_A, PU_A, T_A, DURA, INFOCA)
# PR_X is private key of certification authority
# PU_X is public key of certification authority
# ID_A is user ID,
# PU_A is public key of A,
# T_A is time of issuance of certificate.


class CertificationAuthorityServer(object):
    def __init__(self, host='', port=7171):
        self.host = host
        self.port = port

        # A key-pair generated using: rsa.generate_key_pair(1000037, 1000039)
        self.pub_key = (172946823661, 1000076001443)
        self.pvt_key = (739559892397, 1000076001443)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def run(self):
        print("> Certification authority now listening on port: %d \n" % self.port)

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
        print(">>> New client connected:", address)

        while True:
            try:
                data = client.recv(4096)
                if data:

                    data = data.decode()
                    response = "echo: " + data.decode()

                    client.send(response.encode())
                else:
                    raise socket.timeout()

            except socket.timeout:
                print(">>> Client disconnected: ", address, "\n")
                client.close()
                return False


if __name__ == "__main__":
    CertificationAuthorityServer().run()
