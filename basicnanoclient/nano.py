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

    def public_key_to_account(self: Self, public_key: str) -> str:
        """Convert a public key to a Nano account address.

        Args:
            public_key (str): The public key.

        Returns:
            str: The Nano account address.
        """
        public_key_bytes = binascii.unhexlify(public_key)
        account_prefix = b'00' + public_key_bytes
        checksum = blake2b(account_prefix, digest_size=5).digest()
        encoded_key = base64.b32encode(account_prefix).decode().strip('=').replace('0', 'O').replace('1', 'L')
        encoded_checksum = base64.b32encode(checksum).decode().strip('=').replace('0', 'O').replace('1', 'L')
        return f"nano_{encoded_key}{encoded_checksum[::-1]}"

    def derive_account(self: Self, seed: str, index: int) -> Dict[str, Any]:
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
        # Generate a 64-byte seed in bytes
        if len(seed) != 64:
            raise ValueError("Seed must be a 64-character hexadecimal string")

        seed_bytes = binascii.unhexlify(seed)
        if len(seed_bytes) != 32:
            raise ValueError("Seed must be exactly 32 bytes long when unhexlified")

        index_bytes = index.to_bytes(4, 'big')
        blake2b_hasher = blake2b(digest_size=32)
        blake2b_hasher.update(seed_bytes)
        blake2b_hasher.update(index_bytes)
        private_key = blake2b_hasher.digest()

        sk = SigningKey(private_key)
        vk = sk.verify_key
        public_key = binascii.hexlify(vk.encode()).decode()
        account = self.public_key_to_account(public_key)

        return {
            "private": binascii.hexlify(private_key).decode(),
            "public": public_key,
            "account": account
        }

    def block_create(
            self: Self,
            previous: str,
            account: str,
            representative: str,
            balance: str,
            link: str,
            key: str) -> dict:
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

    def wallet_info(self: Self, wallet: str) -> Dict[str, Any]:
        """Retrieve information about a Nano wallet.

        Args:
            wallet (str): The Nano wallet address.

        Returns:
            A dictionary containing information about the Nano wallet.
        """
        return session.post(self.rpc_network, json={
            "action": "wallet_info",
            "wallet": wallet
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

    def wallet_history(self: Self, wallet: str) -> Dict[str, Any]:
        """Retrieve the transaction history for a Nano wallet.

        Args:
            wallet (str): The Nano wallet address.

        Returns:
            A dictionary containing the transaction history
                for the Nano wallet.
        """
        return session.post(self.rpc_network, json={
            "action": "wallet_history",
            "wallet": wallet
        }).json()

    def account_list(self: Self, wallet: str) -> Dict[str, Any]:
        """Retrieve a list of Nano accounts associated with a wallet.

        Args:
            wallet (str): The Nano wallet address.

        Returns:
            A dictionary containing a list of Nano accounts
            associated with the wallet.
        """
        return session.post(self.rpc_network, json={
            "action": "account_list",
            "wallet": wallet
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
