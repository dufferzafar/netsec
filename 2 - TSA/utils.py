"""Various utility functions."""

import math


def str_to_ints(msg, B):
    """
    Convert a string to a list of integers.

    Each of the integer represents B bytes of string data.
    """

    ints = []
    for block in nsplit(msg, B):

        n = 0
        for c in block:
            n = (n << 8) | ord(c)

        ints.append(n)

    return ints


def ints_to_str(ints, B):
    """
    Convert a list of integers to a string.

    Each of the integer represents B bytes of string data.
    """

    txt = ""
    for i in ints:
        for _ in range(B + 1):
            txt += chr(
                (i & (255 << (8 * B))) >> (8 * B)
            )
            i = i << 8

    return txt


def nsplit(s, n):
    """
    Split a string/list into a list of sublists each of size n.
    """
    return [s[i:i + n] for i in range(0, len(s), n)]


def hex_repr(s):
    return " ".join("%02x" % ord(b) for b in s)


if __name__ == '__main__':
    I = str_to_ints("Shadab Zafar is a good boy.", 2)

    for i in I:
        print(i, math.log(i, 2))
