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


if __name__ == "__main__":
    import doctest
    doctest.testmod()
