import base64
import hashlib
import sys

import rsa


class ClientVerifier(object):
    def __init__(self):

        # A key-pair generated using: rsa.generate_key_pair(1000033, 1000039)
        self.pub_key = (172946823661, 1000072001287)
        self.pvt_key = (613431099685, 1000072001287)

        self.tsa_pub_key = (172946823661, 1000076001443)
        self.requester_pub_key = (172946823661, 1000036000099)

    def run(self):
        stamped_file = sys.argv[1]

        print()
        print("> Given input file:", stamped_file)

        with open(stamped_file) as inp:
            now = inp.readline()
            sig = inp.readline()
            document = inp.read()

        # Decrypt the document using my private key and sender's public key
        doc = rsa.decrypt(document, self.requester_pub_key)
        doc = rsa.decrypt(doc, self.pvt_key)
        now = base64.b64decode(now).decode()
        doc = base64.b64decode(document).decode()

        # Find hash of file
        h1 = hashlib.sha256(doc.encode()).hexdigest()

        print("> Document hash:", h1)

        # Concat the provided time and the document hash
        doc_time = (h1 + "||" + now).encode()
        h2 = hashlib.sha256(doc_time).hexdigest()

        # Decrypt the signature using public key of timestamp authority
        h3 = rsa.decrypt(sig, self.tsa_pub_key)
        h3 = base64.b64decode(sig).decode()

        print()
        if h2 == h3:
            print("> Document has not been modified and was available at: ", now)
        else:
            print("> Document has been modified or it was not signed by the TSA.")


if __name__ == '__main__':
    ClientVerifier().run()
