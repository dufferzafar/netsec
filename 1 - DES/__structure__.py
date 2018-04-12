
DES

def key_schedule(key):

def feistel(R, K):

def substitute(T):

def des(text, key, typ):

    str_to_bits()

    key_schedule()

    # BLOCK loop (~) (File to Blocks)

        get_next_block()

        initial_permutation()

        L, R = nsplit(block, 32)

        # ROUND loop (16)
            fiestel( subkey )

            xor()
            swap()

        inverse_initial_permutation()

    bits_to_str()

def encrypt(plain_text, key):
    des(text, key, typ="encrypt"):

def decrypt(cipher_text, key):
    des(text, key, typ="decrypt"):

