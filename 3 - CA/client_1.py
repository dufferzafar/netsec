import socket


class Client(object):
    def __init__(self, ca_host='', ca_port=7171):
        self.tsa = (ca_host, ca_port)

        # A key-pair generated using: rsa.generate_key_pair(1000003, 1000033)
        self.pub_key = (172946823661, 1000036000099)
        self.pvt_key = (640311959845, 1000036000099)

        self.ca_pub_key = (172946823661, 1000076001443)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.sock.connect(self.tsa)
        except OSError:
            print("> Could not connect. Ensure that the server is running.")
            exit(1)

    def run(self):
        req = "Shadab"
        self.sock.send(req.encode())

        resp = self.sock.recv(4096)
        resp = resp.decode()


if __name__ == '__main__':
    Client().run()
