"""
Data Encryption Standard.

https://csrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf
"""

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


def feistel(R, K):
    """
    Feistel (F) function which operates on right half block and a subkey.

    Page 16 of FIPS.
    https://en.wikipedia.org/wiki/Data_encryption_standard#The_Feistel_(F)_function
    """

    # Apply a permutation that expands the 32 bit half block to 48 bits
    T = utils.permute(R, C.EXPAND)

    # XOR the expanded value with given subkey
    T = utils.xor(T, K)

    # Apply SBoxes to a 48 bit input and return 32 bit output.
    T = substitute(T)

    # Finally, apply the direct permutation P
    T = utils.permute(T, C.P)

    return T


def substitute(T):
    """
    Apply SBoxes to a 48 bit input and return 32 bit output.
    """

    sub = []

    # The given 48 bit block is divided into eight 6 bit pieces
    for i, p in enumerate(utils.nsplit(T, 6)):

        # First and Last bit give the row of SBOX
        row = int(str(p[0]) + str(p[5]), 2)
        # And the other bits give the column
        col = int("".join([str(s) for s in p[1:][:-1]]), 2)

        sub += list(map(int, utils.bits(C.SBOX[i][row][col])))

    return sub


def des(text, key, typ="encrypt"):
    """
    The DES Encryption routine.
    """

    # Clip Key
    if len(key) < 8:
        raise ValueError("key should be atleast 8 Bytes long.")
    elif len(key) > 8:
        print("Key is more than 8 Bytes long; taking first 8 Bytes.")
        key = key[:8]

    if len(text) % 8 != 0:
        print(len(text))
        raise ValueError("text length should be a multiple of 8.")

    # TODO Add padding to data
    text = utils.str_to_bits(text)

    # Generate round keys
    subkeys = key_schedule(key)

    # This will store the result of encryption
    cipher = []

    # Since each block is encrypted independently of other blocks, this is ECB mode
    # TODO Add support for other encryption modes: CBC etc.

    # Store outputs of each round
    # (used to verify that encryption & decryption are inverses of each other)
    round_out = []

    # Split input text into
    for block in utils.nsplit(text, 64):

        # Apply initial permutation to the block
        block = utils.permute(block, C.IP)

        # Split it into two halves
        L, R = utils.nsplit(block, 32)
        print("%2d - L%2d: %s   R%2d: %s" %
              (0, 0, utils.bits_to_hex(L), 0, utils.bits_to_hex(R)))
        round_out.append((utils.bits_to_hex(L), utils.bits_to_hex(R)))

        # The 16 rounds
        for i in range(16):

            # Only the keys change during encryption
            if typ == "encrypt":
                K = subkeys[i]
            else:
                K = subkeys[15 - i]

            T = feistel(R, K)
            T = utils.xor(L, T)
            L = R
            R = T

            print("%2d - L%2d: %s   R%2d: %s  K%2d: %s" %
                  (i + 1, i + 1, utils.bits_to_hex(L), i + 1, utils.bits_to_hex(R), i + 1, utils.bits_to_hex(K)))

            round_out.append((utils.bits_to_hex(L), utils.bits_to_hex(R)))

        # Apply the inverse initial permutation
        cipher += utils.permute(R + L, C.IP_i)

    cipher_text = utils.bits_to_str(cipher)

    return cipher_text, round_out


def encrypt(plain_text, key):
    return des(plain_text, key, typ="encrypt")


def decrypt(cipher_text, key):
    return des(cipher_text, key, typ="decrypt")


# Page 27 of the FIPS Standard
def tdea_encrypt(plain_text, k1, k2, k3):
    """Triple DES Encryption."""
    t0 = plain_text
    t1, x = des(t0, k1, typ="encrypt")
    t2, y = des(t1, k2, typ="decrypt")
    t3, z = des(t2, k3, typ="encrypt")

    return t3


def tdea_decrypt(cipher_text, k1, k2, k3):
    """Triple DES Decryption."""
    t0 = cipher_text
    t1, x = des(t0, k3, typ="decrypt")
    t2, y = des(t1, k2, typ="encrypt")
    t3, z = des(t2, k1, typ="decrypt")

    return t3


if __name__ == '__main__':
    key = "Nevillle"
    plain_text = "Shadab78"

    print("Plain Text (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(plain_text)))
    print("Key (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(key)))
    print("\n")

    cipher_text, encry_rounds = encrypt(plain_text, key)

    print("\n")
    print("Cipher Text (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(cipher_text)))
    print("Key (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(key)))
    print("\n")

    deciphered, decry_rounds = decrypt(cipher_text, key)

    print("\n")
    print("De-ciphered Plain Text (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(deciphered)))

    # Validating that our DES implementation works correctly!
    # First ensure that we recover plain text correctly
    assert (plain_text == deciphered)

    for j in range(len(encry_rounds)):

        LE, RE = encry_rounds[j]
        LD, RD = decry_rounds[16 - j]

        assert LE == RD and RE == LD

    # Triple DES
    print("\n\n TRIPLE-DES \n")
    k1 = "bedazzle"
    k2 = "Miracles"
    k3 = "Logician"
    t_cipher_text = tdea_encrypt(plain_text, k1, k2, k3)
    t_deciphered_text = tdea_decrypt(t_cipher_text, k1, k2, k3)
    print("\nPlain Text (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(plain_text)))

    print("Key 1 (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(k1)))
    print("Key 2 (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(k2)))
    print("Key 3 (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(k3)))

    print("\nCipher Text (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(t_cipher_text)))

    print("Key 3 (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(k3)))
    print("Key 2 (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(k2)))
    print("Key 1 (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(k1)))

    print("\nDeciphered Plain Text (Hexadecimal Format) = %s" %
          utils.bits_to_hex(utils.str_to_bits(t_deciphered_text)))
    assert (plain_text == t_deciphered_text)
