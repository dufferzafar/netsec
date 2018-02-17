
import utils
import constants as C


def key_schedule(key):
    """
    From the given key, generate 16 subkeys to be used in each round.

    Uses constants PC_1 and PC_2.

    Page 20 of the FIPS doc and:
    https://en.wikipedia.org/wiki/Data_encryption_standard#Key_schedule
    """

    keys = []
    key = utils.str_to_bits(key)

    # Apply PC_1 on the key
    # effectively converting a 64 bit key into 56 bits
    key = utils.permute(key, C.PC_1)

    # Split it into two halves
    c, d = utils.nsplit(key, 28)

    for i in range(16):

        # Shift both halves by a specified amount
        c = utils.lshift(c, C.SHIFT[i])
        d = utils.lshift(d, C.SHIFT[i])

        # Apply PC_2 to get a round key of 48 bits
        k = utils.permute(c + d, C.PC_2)

        keys.append(k)

    return keys


def encrypt(plain_text, key):
    """
    The DES Encryption routine.
    """

    # Clip Key
    if len(key) < 8:
        raise ValueError("key should be atleast 8 Bytes long.")
    elif len(key) > 8:
        print("Key is more than 8 Bytes long; taking first 8 Bytes.")
        key = key[:8]

    # TODO: Add padding to data

    if len(plain_text) % 8 != 0:
        print(len(plain_text))
        raise ValueError("plain_text length should be a multiple of 8.")

    # Generate round keys
    subkeys = key_schedule(key)

    print(subkeys)


def decrypt(cipher_text, key):
    raise NotImplementedError


if __name__ == '__main__':
    # TODO: Clip key if len > 8
    key = "Nevillle"

    # TODO: Print plain text in bits, hex etc.
    # plain_text = "I'd want some peace and quiet, if it were me."
    plain_text = "Lovegood"

    cipher_text = encrypt(plain_text, key)
    # deciphered = decrypt(cipher_text, key)
