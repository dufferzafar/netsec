"""Various utility functions."""

from itertools import chain


def str_to_bits(s):
    """
    Convert a string to a list of bits.

    >>> str_to_bits("a")
    [0, 1, 1, 0, 0, 0, 0, 1]

    >>> str_to_bits("ab")
    [0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0]
    """
    return list(map(int, chain.from_iterable(map(bits, s))))


def bits_to_str(b):
    """
    Convert a bitlist to string.

    >>> bits_to_str([0, 1, 1, 0, 0, 0, 0, 1])
    'a'

    >>> bits_to_str([0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0])
    'ab'
    """

    b = list(map(str, b))
    return "".join([chr(int("".join(byte), 2)) for byte in nsplit(b, 8)])


def bits_to_hex(b):
    """
    Convert a bitlist to hex - which is easier to print on screen.

    >>> bits_to_hex([0, 1, 1, 0, 0, 0, 0, 1])
    '61'
    """
    b = list(map(str, b))
    return "".join([hex(int("".join(byte), 2))[2:] for byte in nsplit(b, 8)])


# TODO: Should this return a string or a list?
def bits(x, size=8):
    """
    Return binary value of x as a string of given size.

    0s are prepended if needed.
    x can be an integer or a character. ASCII Table lookup is used.

    >>> bits(8)
    '00001000'
    """

    if isinstance(x, str):
        x = ord(x)

    b = bin(x)[2:]

    # Prepend 0s if necessary
    if len(b) < size:
        b = "0" * (size - len(b)) + b

    return b


def nsplit(s, n):
    """
    Split a string/list into a list of sublists each of size n.
    """
    # NOTE: Subscripts don't raise IndexError to allow things like these.
    return [s[i:i + n] for i in range(0, len(s), n)]


def lshift(b, n):
    """
    Left circular shift a (bit)string by some amount.

    Similar to b << n in C.

    >>> lshift('1001', 2)
    '0110'
    """
    return b[n:] + b[:n]


def permute(inp, perm):
    """
    Apply a permuation on an input string.

    >>> permute('ab', [2, 1])
    'ba'
    """
    # The permutaions are all given in 1 based indexing, so we subtract 1 here
    return [inp[p - 1] for p in perm]


if __name__ == "__main__":
    import doctest
    doctest.testmod()
