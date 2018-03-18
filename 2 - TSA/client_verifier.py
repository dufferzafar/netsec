import hashlib
import sys

import rsa


class ClientVerifier(object):
    def __init__(self):

        self.tsa_pub_key = (172946823661, 1000076001443)
        self.client_pub_key = (172946823661, 1000036000099)

    def run(self):
        input_file = sys.argv[1]

        print()
        print("> Given input file:", input_file)

        with open(input_file) as inp:
            now, sig = inp.read(int(inp.readline())).split("||")
            doc = inp.read()

        # Decrypt the document using public key of sender
        doc = rsa.decrypt(doc, self.client_pub_key)

        # Find hash of file
        h1 = hashlib.sha256(doc.encode()).hexdigest()

        print("> Document hash:", h1)

        # Concat the provided time and the document hash
        doc_time = (h1 + "||" + now).encode()
        h2 = hashlib.sha256(doc_time).hexdigest()

        # Decrypt the document using public key of timestamp authority
        h3 = rsa.decrypt(sig, self.tsa_pub_key)

        if h2 == h3:
            print("> Document has not been modified and was available at: ", now)
        else:
            print("> Document/timestamp has been modified or it was not signed by the TSA.", now)


if __name__ == '__main__':
    ClientVerifier().run()
