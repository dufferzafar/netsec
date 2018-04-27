import hashlib

import rsa


def get_certificate(ca_sock, user_id, user_pub_key, ca_pub_key):

    print("My ID: ", user_id)
    print("My Public Key: ", user_pub_key)

    print("\nSending request for a new certificate to CA")

    req = "REQ_CERT:%s" % user_id
    ca_sock.send(req.encode())

    resp = ca_sock.recv(4096).decode()
    resp = rsa.decrypt(resp, ca_pub_key)

    ca_sock.close()

    return resp


def cert_is_valid(req, ca_pub_key):
    # Split the request into components
    uid, pbk_p, pbk_n, issue_time, certi = req.split("|")
    client_pub_key = (int(pbk_p), int(pbk_n))

    print(">> User ID: ", uid)
    print(">> Public Key: ", client_pub_key)
    print(">> Issue Time: ", issue_time)
    print(">> Certificate: ", certi)

    # All information except the certificate
    all_but_certi = "|".join(req.split("|")[:-1])
    h1 = hashlib.sha256(all_but_certi.encode()).hexdigest()

    # Decrypt the certificate with CA's public key
    h2 = rsa.decrypt(certi, ca_pub_key)

    # Verify that the certificate is correct
    is_valid = h1 == h2
    if is_valid:
        print("\n> Certificate is valid for given public key.")
    else:
        print("\n> Certificate is invalid for given public key.")

    return is_valid, uid, client_pub_key
