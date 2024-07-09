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
                self.accounts.append(self.derive_account(seed, i))

    def validate_accounts(self: Self) -> bool:
        """Validate the accounts in the wallet.

        Returns:
            bool: True if all accounts are valid, False otherwise.
        """
        return all(
            self.validate_account(account["account"])
            for account in self.accounts
        )

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
    
    def encode_account(self: Self, seed_bytes: bytes):
        assert len(seed_bytes) == 32  # Assuming bytes is of length 32 (similar to C++ uint256_t)
        
        destination_a = ""
        check = 0
        hash = hashlib.blake2b(digest_size=5)
        hash.update(seed_bytes)
        check = int.from_bytes(hash.digest(), byteorder='big')  # Ensure correct endianess
        
        number_l = self.number(seed_bytes) << 40 | check
        for i in range(60):
            r = number_l & 0x1f
            number_l >>= 5
            destination_a += self.account_encode(r)
        
        destination_a += "_onan"  # nano_
        destination_a = destination_a[::-1]  # Reverse the string
        
        return destination_a

    def decode_account(self, source_a):
        error = len(source_a) < 5
        if not error:
            xrb_prefix = source_a[0] == 'x' and source_a[1] == 'r' and source_a[2] == 'b' and (source_a[3] == '_' or source_a[3] == '-')
            nano_prefix = source_a[0] == 'n' and source_a[1] == 'a' and source_a[2] == 'n' and source_a[3] == 'o' and (source_a[4] == '_' or source_a[4] == '-')
            node_id_prefix = source_a[0] == 'n' and source_a[1] == 'o' and source_a[2] == 'd' and source_a[3] == 'e' and source_a[4] == '_'
            error = (xrb_prefix and len(source_a) != 64) or (nano_prefix and len(source_a) != 65)
            if not error:
                if xrb_prefix or nano_prefix or node_id_prefix:
                    i = 4 if xrb_prefix else 5
                    if source_a[i] == '1' or source_a[i] == '3':
                        number_l = 0
                        for char in source_a[i:]:
                            character = ord(char)
                            error = character < 0x30 or character >= 0x80
                            if not error:
                                byte = self.account_decode(char)
                                error = byte == '~'
                                if not error:
                                    number_l <<= 5
                                    number_l += byte
                        if not error:
                            temp = number_l >> 40
                            check = number_l & 0xffffffffff
                            validation = 0
                            hash = blake2b(digest_size=5)
                            hash.update(temp.to_bytes(32, 'big'))
                            validation = int.from_bytes(hash.digest(), 'big')
                            error = check != validation
                    else:
                        error = True
                else:
                    error = True
        return error


    def validate_account(self: Self, account: str) -> bool:
        """Validate a Nano account address using checksum.

        Args:
            account (str): The Nano account address.

        Returns:
            bool: True if the account address is valid, False otherwise.
        """
        if len(account) != 64 and len(account) != 65:
            return False

        xrb_prefix = account.startswith("xrb_") and len(account) == 64
        nano_prefix = account.startswith("nano_") and len(account) == 65
        node_prefix = account.startswith("node_") and len(account) == 65

        if not (xrb_prefix or nano_prefix or node_prefix):
            return False

        # Determine start/end indices for account_key and checksum
        prefix_length = 4 if xrb_prefix else 5
        account_key_end = prefix_length + 52
        checksum_start = account_key_end

        account_key = account[prefix_length:account_key_end]
        checksum = account[checksum_start:]

        # Decode account key from Nano base32
        account_bytes = self.decode_nano_base32(account_key)

        # Convert account bytes to hex for Blake2b
        account_bytes_hex = binascii.hexlify(account_bytes).decode()
        account_bytes_hex = bytes.fromhex(account_bytes_hex)

        # Compute the expected checksum
        computed_checksum = blake2b(account_bytes_hex, digest_size=5).digest()
        computed_checksum = self.encode_nano_base32(computed_checksum)

        return checksum == computed_checksum
        # return not self.decode_account(account)
        # prefix_length = 5  # 'nano_' prefix
        # account_key = account[prefix_length:prefix_length + 52]
        # checksum = account[prefix_length + 52:]
        # account_bytes = Utils.decode_nano_base32(account_key)
        # computed_checksum = blake2b(account_bytes, digest_size=5).digest()
        # computed_checksum = Utils.encode_nano_base32(computed_checksum[::-1])
        # return checksum == computed_checksum

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
        public_key = self.key_expand(private_key)["public"]

        return {
            "private": private_key,
            "public": public_key
        }

    def encode_nano_base32(self: Self, data: bytes) -> str:
        """Encode bytes into a Nano base32 string."""
        base32_string = ""
        length = len(data)
        for i in range(0, length, 5):
            chunk = data[i:i+5]
            num = int.from_bytes(chunk, 'big')
            block = ""
            for _ in range(8):
                block = self.NANO_ALPHABET[num & 31] + block
                num >>= 5
            base32_string += block
        return base32_string[:(length * 8 + 4) // 5]

    def public_key_to_account(self: Self, public_key: str) -> str:
        """Convert a public key to a Nano account address.

        Args:
            public_key (str): The public key.

        Returns:
            str: The Nano account address.
        """
        # public_key_bytes = binascii.unhexlify(public_key)

        # # Encode the public key in Nano's base32 format
        # account_prefix = 'nano_'
        # account_key = self.encode_nano_base32(public_key_bytes)

        # # Compute the checksum
        # checksum = blake2b(public_key_bytes, digest_size=5).digest()
        # checksum = self.encode_nano_base32(checksum)
        # return f"{account_prefix}{account_key}{checksum}"

        # Verify the public key length (should be 32 bytes for Nano)
        if len(public_key) != 32:
            raise ValueError("Public key must be 32 bytes long.")

        # Step 1: Encode the public key using Nano's base32 encoding
        encoded_public_key = self.encode_nano_base32(public_key)

        # Step 2: Compute the checksum (first 5 bytes of the blake2b hash of the public key in reverse order)
        checksum = hashlib.blake2b(public_key, digest_size=5).digest()
        reversed_checksum = checksum[::-1]  # Reverse the checksum
        encoded_checksum = self.encode_nano_base32(reversed_checksum)

        # Step 3: Combine the encoded public key and the checksum to form the address
        nano_address = f"nano_{encoded_public_key}{encoded_checksum}"
        
        return nano_address

    def derive_account(self: Self, seed: str, index: int) -> Dict[str, str]:
        """Derive a Nano account from a seed and index.

        Args:
            seed (str): A 64-character hexadecimal string representing the
                Nano seed.
            index (int): The account index.

        Returns:
            A dictionary with keys 'public' and 'account', where 'public' is a
            64-character hexadecimal string representing
            the Nano public key and 'account' is the Nano account address.
        """
        if len(seed) != 64:
            raise ValueError("Seed must be a 64-character hexadecimal string")

        seed_bytes = binascii.unhexlify(seed)
        if len(seed_bytes) != 32:
            raise ValueError("Seed must be exactly 32 bytes long when unhexlified")

        key_pair = self.generate_account_key_pair(seed, index)

        # get account from public key
        # public_key_bytes = binascii.unhexlify(key_pair["public"])
        # account = self.public_key_to_account(public_key_bytes)
        key = self.key_expand(key_pair["private"])

        return {
            "private": key_pair["private"],
            "public": key["public"],
            "account": key["account"]
        }

    def block_create(
            self: Self,
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
            "work": self.generate_work(previous)
        }
        return block

    def generate_work(self: Self, previous: str) -> str:
        """Generate work for a Nano block.

        Args:
            block (str): The block hash.

        Returns:
            str: The work value.
        """
        target = 0xFFFFFFF800000000  # Nano's default threshold
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