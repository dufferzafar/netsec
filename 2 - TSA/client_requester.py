import socket
import sys
import hashlib
import os


class ClientRequester(object):
    def __init__(self, tsa_host='', tsa_port=7171):
        self.tsa = (tsa_host, tsa_port)

        # TODO: Hardcode the public key of the tsa
        # self.tsa_pub_key =

        # First twin prime pair after 1 billion
        # These are the P, Q fed into RSA
        # self.primes = (1000000093, 1000000097)

        # self.pub_key =
        # self.pvt_key =

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.sock.connect(self.tsa)
        except OSError:
            print("> Could not connect. Ensure that the server is running.")
            exit(1)

    def run(self):
        # TODO: Proper CLI?
        input_file = sys.argv[1]

        # TODO: Proper os.path.split*
        name, ext = os.path.splitext(input_file)
        output_file = name + "_stamped" + ext

        print()
        print("> Given input file:", input_file)

        with open(input_file, "rb") as inp:
            dhash = hashlib.sha256(inp.read()).hexdigest()

        print("> Sending document hash to server:", dhash, "\n")

        resp = "HASH: " + dhash
        self.sock.send(resp.encode())

        # TODO: try/except in case something goes wrong?
        data = self.sock.recv(1024)
        data = data.decode()
        print("> Received from server:", data, "\n")

        data = data.split("||")
        now, sig = data[0], data[1]

        print("> Dumping data to:", output_file)
        with open(output_file, "w") as out:
            # out.write(rsa.encrypt(input_file, self.pvt_key))
            out.write("INPUT")
            out.write("\n")
            out.write(now)
            out.write("\n")
            out.write(sig)
            out.write("\n")

        # print("This file can now be shared securely.")


if __name__ == '__main__':
    ClientRequester().run()
