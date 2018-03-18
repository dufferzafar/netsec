import hashlib
import os
import socket
import sys

import rsa


class ClientRequester(object):
    def __init__(self, tsa_host='', tsa_port=7171):
        self.tsa = (tsa_host, tsa_port)

        # A key-pair generated using: rsa.generate_key_pair(1000003, 1000033)
        self.pub_key = (172946823661, 1000036000099)
        self.pvt_key = (640311959845, 1000036000099)

        self.tsa_pub_key = (172946823661, 1000076001443)
        self.verifier_pub_key = (172946823661, 1000072001287)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.sock.connect(self.tsa)
        except OSError:
            print("> Could not connect. Ensure that the server is running.")
            exit(1)

    def run(self):
        input_file = sys.argv[1]

        name, ext = os.path.splitext(input_file)
        output_file = name + "_stamped" + ext

        print()
        print("> Given input file:", input_file)

        with open(input_file, "rb") as inp:
            input_data = inp.read()
            dhash = hashlib.sha256(input_data).hexdigest()

        print("> Sending document hash to server:", dhash, "\n")

        resp = "HASH: " + dhash
        self.sock.send(resp.encode())

        data = self.sock.recv(4096)
        data = data.decode()

        # print("> Received from server:", data, "\n")
        print("> Received timestamp & signature from server")

        print("> Dumping data to:", output_file)
        with open(output_file, "w") as out:
            out.write("%d\n" % len(data))
            out.write(data)

            doc = input_data.decode()
            doc = rsa.encrypt(doc, self.verifier_pub_key)
            doc = rsa.encrypt(doc, self.pvt_key)
            out.write(doc)

            # Ensure that decryption is OK
            # dec_doc = rsa.decrypt(enc_doc, self.pub_key)
            # assert doc == dec_doc

        # print("This file can now be shared securely.")


if __name__ == '__main__':
    ClientRequester().run()
