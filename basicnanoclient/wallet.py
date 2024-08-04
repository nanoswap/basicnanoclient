__package__ = "basicnanoclient"

from typing import Any, Dict, Self
import binascii
import struct
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder
from ed25519_blake2b import SigningKey
from binascii import hexlify, unhexlify
from hashlib import blake2b
import hashlib
import requests
import random
import os

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
        signing_key = SigningKey(binascii.unhexlify(key))
        # private_key = signing_key.to_bytes().hex()
        public_key = signing_key.get_verifying_key().to_bytes()
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
    def sign_block(block: dict, private_key: str) -> str:
        """Sign a block using a private key.

        Args:
            block (dict): The block to sign.
            private_key (str): The private key to sign the block with.

        Returns:
            str: The signature of the block.
        """
        # Create signing key from the private key bytes
        signing_key = SigningKey(unhexlify(private_key))

        # Convert balance from decimal to hexadecimal and pad to 32 characters
        balance_hex = hex(int(block["balance"]))[2:].zfill(32)

        # Determine block type and prepare the block contents to be signed
        block_type = block["type"]
        if block_type == "state":
            block_contents = (
                unhexlify("0000000000000000000000000000000000000000000000000000000000000006") +
                unhexlify(Utils.nano_address_to_public_key(block["account"])) +
                unhexlify(block["previous"]) +
                unhexlify(Utils.nano_address_to_public_key(block["representative"])) +
                unhexlify(balance_hex) +
                unhexlify(block["link"])
            )
        else:
            raise ValueError("Unsupported block type: {}".format(block_type))

        # Hash the block contents
        block_hash = blake2b(block_contents, digest_size=32).digest()

        # Sign the hash
        signed_message = signing_key.sign(block_hash)

        # Convert the signature to hex and return it
        return hexlify(signed_message).decode()

    @staticmethod
    def generate_work_rpc(hash: str, rpc_network: str = "http://127.0.0.1:17076") -> str:
        """Generate work for a given hash.

        Args:
            hash (str): The hash to generate work for.
            rpc_network (str): The RPC network to use.

        Returns:
            str: The generated work.
        """
        session = requests.Session()
        response = session.post(rpc_network, json={
            "action": "work_generate",
            "hash": hash,
            "multiplier": "1.0"
        }).json()
        print(response)
        return response['work']
