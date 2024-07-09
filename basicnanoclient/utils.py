__package__ = "basicnanoclient"

from typing import Any, Dict, Self
import binascii
import requests
import random
import base64
import struct
import os
import hashlib
import sys
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder
from hashlib import blake2b


class uint256_t(int):
    def __new__(cls, value):
        return super().__new__(cls, value % 2**256)

class uint256_union:
    def __init__(self, bytes):
        self.bytes = bytes

    def number(self):
        # Assuming self.bytes is a bytes object of length 32 (similar to C++ uint256_t)
        result = int.from_bytes(self.bytes, byteorder=sys.byteorder)
        return uint256_t(result)

class Utils():
    """Utility functions for working with Nano."""
    _CHARS = "13456789abcdefghijkmnopqrstuwxyz"
    NANO_ALPHABET = '13456789abcdefghijkmnopqrstuwxyz'
    base32_alphabet = '13456789abcdefghijkmnopqrstuwxyz'
    account_lookup = "13456789abcdefghijkmnopqrstuwxyz"
    account_reverse = "~0~1234567~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~89:;<=>?@AB~CDEFGHIJK~LMNO~~~~~"

    @staticmethod
    def generate_seed() -> str:
        """Generate a new Nano seed.

        Returns:
            str: A 64-character hexadecimal string representing the Nano seed.
        """
        return binascii.hexlify(os.urandom(32)).decode()

    @staticmethod
    def dec_to_hex(d: int, n: int) -> str:
        """Convert a decimal number to a hexadecimal string.

        Args:
            d (int): The decimal number to convert.
            n (int): The number of characters in the hexadecimal string.

        Returns:
            str: The hexadecimal string.
        """
        return format(d, "0{}X".format(n*2))

    @staticmethod
    def is_hex(h: str) -> bool:
        """Check if a string is a valid hexadecimal string.

        Args:
            h (str): The string to check.

        Returns:
            bool: True if the string is a valid hexadecimal string, False otherwise
        """
        try:
            binascii.unhexlify(h)
            return True
        except binascii.Error:
            return False

    # def encode_nano_base32(self: Self, bytes_data: bytes) -> str:
    #     bitarr_bits = len(bytes_data) * 8
    #     leftover = 5 - (bitarr_bits % 5)
    #     bitarr_bits += leftover

    #     bitarr = [0] * bitarr_bits

    #     index = leftover
    #     for byte in bytes_data:
    #         for i in range(8):
    #             bitarr[index] = (byte >> (7 - i)) & 1
    #             index += 1

    #     result = []
    #     for i in range(0, bitarr_bits, 5):
    #         byte = 0
    #         for j in range(5):
    #             byte = (byte << 1) | bitarr[i + j]
    #         result.append(self.NBASE32_CHARS[byte])

    #     return ''.join(result)

    @staticmethod
    def decode_nano_base32(data: str) -> bytes:
        """Decode a Nano base32 encoded string.

        Args:
            data (str): The encoded data.

        Returns:
            bytes: The decoded data.
        """
        base32_table = {char: i for i, char in enumerate(Utils.base32_alphabet)}
        bits = ''.join(f'{base32_table[char]:05b}' for char in data)
        # Remove padding bits added during encoding
        padding_length = (8 - len(bits) % 8) % 8
        bits = bits[:-padding_length] if padding_length else bits
        result = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
        return result

    @staticmethod
    def number(seed_bytes: bytes):
        return uint256_union(seed_bytes).number()

    @staticmethod
    def account_encode(value):
        assert value < 32
        result = Utils.account_lookup[value]
        return result

    @staticmethod
    def account_decode(value):
        assert ord(value) >= ord('0')
        assert ord(value) <= ord('~')
        result = Utils.account_reverse[ord(value) - 0x30]
        if result != '~':
            result = ord(result) - 0x30
        return result