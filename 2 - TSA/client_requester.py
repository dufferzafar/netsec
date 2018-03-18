import hashlib
import os
import socket
import sys

import rsa


class ClientRequester(object):
    def __init__(self, tsa_host='', tsa_port=7171):
        self.tsa = (tsa_host, tsa_port)

        # TODO: Hardcode the public key of the tsa
        # self.tsa_pub_key =

        # A key-pair generated using: rsa.generate_key_pair(1000003, 1000033)
        self.pub_key = (172946823661, 1000036000099)
        self.pvt_key = (640311959845, 1000036000099)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.sock.connect(self.tsa)
        except OSError:
            print("> Could not connect. Ensure that the server is running.")
            exit(1)

    def run(self):
        # TODO: Proper CLI?
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

        data = data.split("||")
        now, sig = data[0], data[1]

        print("> Dumping data to:", output_file)
        with open(output_file, "w") as out:
            out.write(rsa.encrypt(input_data.decode("ascii"), self.pvt_key))
            out.write("\n")
            out.write(now)
            out.write("\n")
            out.write(sig)
            out.write("\n")

        # print("This file can now be shared securely.")


if __name__ == '__main__':
    ClientRequester().run()
