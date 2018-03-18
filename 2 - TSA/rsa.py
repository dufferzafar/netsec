"""
The RSA algorithm.

https://en.wikipedia.org/wiki/RSA_(cryptosystem)
"""

import binascii
import random
import math

import utils

# Removes non-determinism from the code
random.seed(100001)


def egcd(a, b):
    """
    Euclid's Extended GCD algorithm.

    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    """

    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    """
    Modular inverse using the e-GCD algorithm.

    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Computing_multiplicative_inverses_in_modular_structures
    """

    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m


def generate_key_pair(p, q):
    """
    Generate a key-pair.
    """

    n = p * q
    phi = (p - 1) * (q - 1)

    # Find e such that e & phi are co-prime
    while True:
        e = random.randrange(3, phi)
        g, _, _ = egcd(e, phi)

        if g == 1:
            break

    d = modinv(e, phi)

    return (e, n), (d, n)


def encrypt(msg, key):
    k, n = key
    nbytes = int(math.log(n, 2) // 8)

    cipher = [pow(p, k, n) for p in utils.str_to_ints(msg, nbytes)]
    cipher = utils.ints_to_str(cipher, nbytes + 1)
    # cipher = binascii.hexlify(cipher.encode()).decode()
    return cipher


def decrypt(cipher, key):
    k, n = key
    nbytes = int(math.log(n, 2) // 8)

    # plain = binascii.unhexlify(cipher.encode()).decode()
    plain = [pow(p, k, n) for p in utils.str_to_ints(cipher, nbytes + 1)]
    plain = utils.ints_to_str(plain, nbytes)

    return plain


if __name__ == '__main__':
    # pv, pu = generate_key_pair(1000000093, 1000000097)
    pv, pu = generate_key_pair(101, 103)

    pln = "Shadab Zafar is a good boy."
    enc = encrypt(pln, pv)
    dec = decrypt(enc, pu)

    assert pln == dec
    print(pln)
