import datetime
import hashlib
import threading
import socket

import rsa


class TimestampServer(object):
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
        print("> Timestamp authority now listening on port: %d \n" % self.port)

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
                    if data.startswith("HASH: "):
                        dhash = data.lstrip("HASH: ")
                        print("> Received a document's hash: %s" % dhash)

                        now = str(datetime.datetime.utcnow())

                        doc_time = (dhash + "||" + now).encode("ascii")
                        nhash = hashlib.sha256(doc_time).hexdigest()

                        sig = rsa.encrypt(nhash, self.pvt_key)

                        response = now + "||" + sig
                        # print("> Sending to client:", response)
                    else:
                        response = "echo: " + data.decode()

                    client.send(response.encode())
                else:
                    raise socket.timeout()

            except socket.timeout:
                    print(">>> Client disconnected: ", address, "\n")
                    client.close()
                    return False


if __name__ == "__main__":
    # TODO: Get port from CLI
    TimestampServer().run()
