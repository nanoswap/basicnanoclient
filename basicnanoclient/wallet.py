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
import sys

from .utils import Utils


class Wallet():
    """Nano Wallet class."""
    _CHARS = "13456789abcdefghijkmnopqrstuwxyz"
    NANO_ALPHABET = '13456789abcdefghijkmnopqrstuwxyz'
    base32_alphabet = '13456789abcdefghijkmnopqrstuwxyz'
    account_lookup = "13456789abcdefghijkmnopqrstuwxyz"
    account_reverse = "~0~1234567~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~89:;<=>?@AB~CDEFGHIJK~LMNO~~~~~"

    def __init__(self: Self, seed: str = None, account_count: int = 0) -> None:
        """Initialize the NanoWallet class.

        Args:
            seed (str): The seed to use for the wallet.
        """
        self.seed = seed
        self.accounts = []
        if seed:
            for i in range(account_count):
                self.accounts.append(self.generate_account_key_pair(seed, i))

    def validate_key_pairs(self: Self) -> bool:
        """Validate the key pairs in the wallet.

        Returns:
            bool: True if all key pairs are valid, False otherwise.
        """
        return all(
            self.validate_key_pair(account["private"], account["public"])
            for account in self.accounts
        )

    def validate_key_pair(self: Self, private_key: str, public_key: str) -> bool:
        """Validate that a private key matches a public key.

        Args:
            private_key (str): The private key in hexadecimal format.
            public_key (str): The public key in hexadecimal format.

        Returns:
            bool: True if the key pair is valid, False otherwise.
        """
        sk = SigningKey(binascii.unhexlify(private_key))
        vk = VerifyKey(binascii.unhexlify(public_key))
        message = b"test message"
        signed = sk.sign(message)
        try:
            vk.verify(signed.message, signed.signature)
            return True
        except Exception:
            return False

    def key_expand(self: Self, key: str) -> Dict[str, Any]:
        """Expand a private key into a public key and account address.

        Args:
            key (str): A 64-character hexadecimal string representing the
                Nano private key.

        Returns:
            A dictionary with keys 'public' and 'account', where 'public' is a
            64-character hexadecimal string representing
            the Nano public key and 'account' is the Nano account address.
        """
        sk = SigningKey(binascii.unhexlify(key))
        vk = sk.verify_key
        public_key = vk.encode(RawEncoder)  # Get the raw bytes directly
        account = self.public_key_to_account(public_key)
        return {"public": public_key.hex(), "account": account}

    def generate_account_private_key(self: Self, seed: str, index: int) -> str:
        """Generate a new account private key from a seed and index.

        Args:
            seed (str): A 64-character hexadecimal string representing the
                Nano seed.
            index (int): The account index.

        Returns:
            str: A 64-character hexadecimal string representing the
                Nano private key.
        """
        if len(seed) != 64 or not Utils.is_hex(seed):
            raise ValueError("Seed must be a 64-character hexadecimal string")

        if not isinstance(index, int):
            raise ValueError("Index must be an integer")

        account_bytes = binascii.unhexlify(Utils.dec_to_hex(index, 4))
        context = blake2b(digest_size=32)
        context.update(binascii.unhexlify(seed))
        context.update(account_bytes)

        new_key = context.hexdigest()
        return new_key

    def generate_account_key_pair(self: Self, seed: str, index: int) -> Dict[str, str]:
        """Generate a new account key pair from a seed and index.

        Args:
            seed (str): A 64-character hexadecimal string representing the
                Nano seed.
            index (int): The account index.

        Returns:
            AccountKeyPair: The account key pair.
        """
        private_key = self.generate_account_private_key(seed, index)
        keys = self.key_expand(private_key)

        return {
            "private": private_key,
            "public": keys["public"],
            "account": keys["account"]
        }

    def public_key_to_account(self: Self, public_key: str) -> str:
        """Convert a public key to a Nano account address.

        Args:
            public_key (str): The public key.

        Returns:
            str: The Nano account address.
        """
        if len(public_key) != 32:
            raise ValueError("Public key must be 32 bytes.")

        # Encode public key to Nano base32
        encoded_public_key = Utils.encode_nano_base32(public_key).rjust(52, '1')

        # Calculate checksum
        checksum = blake2b(public_key, digest_size=5).digest()
        checksum_reversed = checksum[::-1]  # Reverse the checksum bytes

        # Encode checksum to Nano base32
        encoded_checksum = Utils.encode_nano_base32(checksum_reversed).rjust(8, '1')

        # Form the account address
        account = f"nano_{encoded_public_key}{encoded_checksum}"
        return account

    @staticmethod
    def block_create(
            previous: str,
            account: str,
            representative: str,
            balance: str,
            link: str,
            key: str) -> Dict[str, Any]:
        """Create a new block.

        Args:
            previous (str): The previous block hash.
            account (str): The account address.
            representative (str): The representative address.
            balance (str): The new account balance.
            link (str): The link to a previous block.
            key (str): The account private key.

        Returns:
            dict: A dictionary containing information
                about the newly created block.
        """
        sk = SigningKey(binascii.unhexlify(key))
        previous_hash = blake2b(digest_size=32)
        previous_hash.update(previous.encode())
        link_hash = blake2b(digest_size=32)
        link_hash.update(link.encode())

        block = {
            "type": "state",
            "account": account,
            "previous": previous,
            "representative": representative,
            "balance": balance,
            "link": link,
            "link_as_account": link,
            "signature": sk.sign(previous_hash.digest() + link_hash.digest()).signature.hex(),
            "work": Wallet.generate_work(previous)
        }
        return block

    @staticmethod
    def generate_work(previous: str) -> str:
        """Generate work for a Nano block.

        Args:
            block (str): The block hash.

        Returns:
            str: The work value.
        """
        target = 0xfffffff93c41ec94  # Nano's default threshold
        nonce = random.getrandbits(64)
        while True:
            work = struct.pack('>Q', nonce)
            h = blake2b(digest_size=8)
            h.update(work)
            h.update(binascii.unhexlify(previous))
            if int.from_bytes(h.digest(), byteorder='big') >= target:
                break
            nonce += 1
        return binascii.hexlify(work).decode()