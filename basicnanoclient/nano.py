__package__ = "basicnanoclient"

from typing import Any, Dict, Self
import binascii
import requests
import random
import base64
import struct
import os
from nacl.signing import SigningKey, VerifyKey
from hashlib import blake2b

rpc_network: str = "http://127.0.0.1:17076"
session: requests.Session = requests.Session()


class BasicNanoClient():
    """Nano RPC Client.

    ```py
    >>> from basicnanoclient.nano import BasicNanoClient
    >>> client = BasicNanoClient("http://127.0.0.1:17076")
    >>> client.send(...)
    ```
    """

    def __init__(self: Self, rpc_network: str) -> None:
        """Constructor."""
        self.rpc_network = rpc_network

    # Utils

    def dec_to_hex(self: Self, d: int, n: int) -> str:
        """Convert a decimal number to a hexadecimal string.

        Args:
            d (int): The decimal number to convert.
            n (int): The number of characters in the hexadecimal string.

        Returns:
            str: The hexadecimal string.
        """
        return format(d, "0{}X".format(n*2))

    def is_hex(self: Self, h: str) -> bool:
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

    def encode_nano_base32(self: Self, data: bytes) -> str:
        """Encode bytes using Nano's base32 alphabet.

        Args:
            data (bytes): The data to encode.

        Returns:
            str: The encoded data.
        """
        base32_alphabet = '13456789abcdefghijkmnopqrstuwxyz'
        bits = ''.join(f'{byte:08b}' for byte in data)
        # Pad bits to be a multiple of 5
        padding = (5 - len(bits) % 5) % 5
        bits = bits + '0' * padding
        result = ''.join(base32_alphabet[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))
        return result

    def decode_nano_base32(self: Self, data: str) -> bytes:
        """Decode a Nano base32 encoded string.

        Args:
            data (str): The encoded data.

        Returns:
            bytes: The decoded data.
        """
        base32_alphabet = '13456789abcdefghijkmnopqrstuwxyz'
        base32_table = {char: i for i, char in enumerate(base32_alphabet)}
        bits = ''.join(f'{base32_table[char]:05b}' for char in data)
        # Remove padding bits added during encoding
        padding_length = (8 - len(bits) % 8) % 8
        bits = bits[:-padding_length] if padding_length else bits
        result = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
        return result

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

    # Local Functions

    def generate_seed(self: Self) -> str:
        """Generate a new Nano seed.

        Returns:
            str: A 64-character hexadecimal string representing the Nano seed.
        """
        return binascii.hexlify(os.urandom(32)).decode()

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
        public_key = binascii.hexlify(vk.encode()).decode()
        account = self.public_key_to_account(public_key)
        return {"public": public_key, "account": account}

    def generate_account_private_key(self: Self, seed: str, index: int):
        """Generate a new account private key from a seed and index.

        Args:
            seed (str): A 64-character hexadecimal string representing the
                Nano seed.
            index (int): The account index.

        Returns:
            str: A 64-character hexadecimal string representing the
                Nano private key.
        """
        if len(seed) != 64 or not self.is_hex(seed):
            raise ValueError("Seed must be a 64-character hexadecimal string")

        if not isinstance(index, int):
            raise ValueError("Index must be an integer")

        account_bytes = binascii.unhexlify(self.dec_to_hex(index, 4))
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

    def public_key_to_account(self: Self, public_key: str) -> str:
        """Convert a public key to a Nano account address.

        Args:
            public_key (str): The public key.

        Returns:
            str: The Nano account address.
        """
        public_key_bytes = binascii.unhexlify(public_key)

        # Encode the public key in Nano's base32 format
        account_prefix = 'nano_'
        account_key = self.encode_nano_base32(public_key_bytes)

        # Compute the checksum
        checksum = blake2b(public_key_bytes, digest_size=5).digest()
        checksum = self.encode_nano_base32(checksum)
        return f"{account_prefix}{account_key}{checksum}"

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
        account = self.public_key_to_account(key_pair["public"])

        return {
            "private": key_pair["private"],
            "public": key_pair["public"],
            "account": account
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

    # RPC Functions

    def receive(
            self: Self,
            wallet: str,
            account: str,
            block: str) -> Dict[str, Any]:
        """Receives a pending Nano block and adds it to the wallet's balance.

        Args:
            wallet (str): The Nano wallet ID.
            account (str): The Nano account address.
            block (str): A Nano block hash.

        Returns:
            A dictionary representing the received block.

        Raises:
            requests.exceptions.RequestException: due to the RPC request.
        """
        return session.post(self.rpc_network, json={
            "action": "receive",
            "wallet": wallet,
            "account": account,
            "block": block
        }).json()

    def account_info(self: Self, account: str) -> Dict[str, Any]:
        """Retrieve information about a Nano account.

        Including its balance and representative.

        Args:
            account (str): The Nano account address.

        Returns:
            A dictionary with various account information, including:
                'frontier', 'balance', 'representative', and 'block_count'.

        Raises:
            requests.exceptions.RequestException: due to the RPC request.
        """
        return session.post(self.rpc_network, json={
            "action": "account_info",
            "representative": "true",
            "account": account
        }).json()

    def account_key(self: Self, account: str) -> Dict[str, Any]:
        """Retrieve the public key of a Nano account.

        Args:
            account (str): The Nano account address.

        Returns:
            A dictionary with the public key of the Nano account.
        """
        return session.post(self.rpc_network, json={
            "action": "account_key",
            "account": account
        }).json()

    def ledger(self: Self, account: str, count: int) -> Dict[str, Any]:
        """Retrieve the transaction history for a Nano account.

        Args:
            account (str): The Nano account address.
            count (int): The maximum number of transactions to retrieve.

        Returns:
            A dictionary containing the transaction history
                for the Nano account.
        """
        return session.post(self.rpc_network, json={
            "action": "ledger",
            "account": account,
            "count": count
        }).json()

    def receivable(
            self: Self,
            account: str,
            count: int = 1,
            threshold: int = 1) -> Dict[str, Any]:
        """Retrieve a list of pending Nano transactions for an account.

        Args:
            account (str): The Nano account address.
            count (int): The maximum number of transactions to retrieve
                (default is 1).
            threshold (int): The minimum amount of Nano pending in raw units
                (default is 1 raw Nano).

        Returns:
            A dictionary containing a list of pending Nano transactions
                for the account.
        """
        return session.post(self.rpc_network, json={
            "action": "receivable",
            "account": account,
            "count": count,
            "threshold": threshold,
            "source": "true"
        }).json()

    def block_info(self: Self, block: str) -> dict:
        """Retrieve information about a Nano block.

        Args:
            block (str): The block hash.

        Returns:
            dict: A dictionary containing information about the block.
        """
        return session.post(self.rpc_network, json={
            "action": "block_info",
            "json_block": "true",
            "hash": block
        }).json()

    def process(self: Self, block: dict) -> dict:
        """Process a block.

        Args:
            block (dict): The block to be processed.

        Returns:
            dict: A dictionary containing information about the block.
        """
        response = requests.post(self.rpc_network, json={
            "action": "process",
            "block": block
        })
        return response.json()

    def sign_and_send(
            self: Self,
            previous: str,
            account: str,
            representative: str,
            balance: str,
            link: str,
            key: str) -> dict:
        """Sign and send a transaction.

        Args:
            previous (str): The previous block hash.
            account (str): The account address.
            representative (str): The representative address.
            balance (str): The new account balance.
            link (str): The link to a previous block.
            key (str): The account private key.

        Returns:
            dict: A dictionary containing information
                about the transaction.
        """
        # Create the block
        block = self.block_create(
            previous,
            account,
            representative,
            balance,
            link,
            key
        )

        # Process the block
        response = self.process(block)

        return response

    def send(
            self: Self,
            wallet: str,
            source: str,
            destination: str,
            amount: int,
            key: str) -> Dict[str, Any]:
        """Send a specified amount of Nano from one account to another.

        Args:
            wallet (str): The Nano wallet address.
            source (str): The Nano account address to send from.
            destination (str): The Nano account address to send to.
            amount (int): The amount of Nano to send in raw units.
            key (str): The private key of the account sending the Nano.

        Returns:
            A dictionary containing information about the transaction.
        """
        # Retrieve the wallet info
        wallet_info = self.wallet_info(wallet)
        key = wallet_info.get(key)

        # Retrieve the account info
        account_info = self.account_info(source)
        previous = account_info.get('frontier')
        representative = account_info.get('representative')

        # Calculate new balance after sending the amount
        # Convert balance to int for calculations
        current_balance = int(account_info.get('balance'))
        # Subtract amount to be sent and convert back to str
        new_balance = str(current_balance - amount)

        # Sign and send the transaction
        return self.sign_and_send(
            previous,
            source,
            representative,
            new_balance,
            destination,
            key
        )
