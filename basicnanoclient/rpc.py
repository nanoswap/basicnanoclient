__package__ = "basicnanoclient"

import json
from typing import Any, Dict, Self
import requests
from hashlib import blake2b
import binascii
import ed25519
from bitstring import BitArray

from .utils import Utils
from .wallet import Wallet

rpc_network: str = "http://127.0.0.1:17076"
session: requests.Session = requests.Session()

class RPC():
    """Nano RPC Client.

    ```py
    >>> from basicnanoclient.rpc import RPC
    >>> client = RPC("http://127.0.0.1:17076")
    >>> client.send(...)
    ```
    """

    def __init__(self: Self, rpc_network: str) -> None:
        """Constructor."""
        self.rpc_network = rpc_network

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

    def account_representative(self: Self, account: str) -> dict:
        """Retrieve the representative for a Nano account.

        Args:
            account (str): The Nano account address.

        Returns:
            dict: A dictionary containing the representative for the account.
        """
        return session.post(self.rpc_network, json={
            "action": "account_representative",
            "account": account
        }).json()

    def work_validate(self: Self, work: str, hash: str) -> dict:
        """Validate a proof of work.

        Args:
            work (str): The proof of work.
            hash (str): The block hash.

        Returns:
            dict: A dictionary containing information about the proof of work.
        """
        return session.post(self.rpc_network, json={
            "action": "work_validate",
            "work": work,
            "hash": hash
        }).json()

    def process(self: Self, block: dict, sub_type: str = "send") -> dict:
        """Process a block.

        Args:
            block (dict): The block to be processed.

        Returns:
            dict: A dictionary containing information about the block.
        """
        request = {
            "action": "process",
            "json_block": "true",
            "sub_type": sub_type,
            "block": block
        }
        response = requests.post(self.rpc_network, json=request)
        return response.json()

    def receive_all(self: Self):
        pass

    def receive(self: Self):
        pass

    def send(
            self: Self,
            source: str,
            destination: str,
            amount: int,
            key: str,
            work: str = None) -> Dict[str, Any]:
        """Send a specified amount of Nano from one account to another.

        Args:
            source (str): The Nano account address to send from.
            destination (str): The Nano account address to send to.
            amount (int): The amount of Nano to send in raw units.
            key (str): The private key of the account sending the Nano.
            work (str): The proof of work for the block.

        Returns:
            A dictionary containing information about the transaction.
        """
        account_info = self.account_info(source)
        previous = account_info["frontier"]
        balance = int(account_info["balance"])

        # Calculate the new balance after sending
        new_balance = balance - amount

        # Representative can be the same as the source account or a dedicated representative
        representative = source

        # Generate work for the previous block
        if work is None:
            work = Wallet.generate_work_rpc(previous, self.rpc_network)

        # Get public key for the destination account
        destination_public_key = Utils.nano_address_to_public_key(destination)

        # Create the send block
        block = {
            "type": "state",
            "account": source,
            "previous": previous,
            "representative": representative,
            "balance": str(new_balance),
            "link": destination_public_key,
            "signature": "",
            "work": work
        }

        # Sign the block
        block["signature"] = Wallet.sign_block(block, key)

        # Process the block
        response = self.process(block, "send")
        return response

    def open_account(self: Self, account: str, private_key: str, public_key: str, send_block_hash: str, received_amount: str, work: str = None) -> dict:
        """Open a new Nano account.

        Args:
            account (str): The account to open.
            private_key (str): The private key of the account.
            public_key (str): The public key of the account.
            send_block_hash (str): The hash of the first block.
            received_amount (str): The balance of the account.
            work (str): The proof of work for the block.

        Returns:
            dict: A dictionary containing information about the transaction.
        """
        previous = '0000000000000000000000000000000000000000000000000000000000000000'
        representative = account

        # Generate work using public key
        if work is None:
            work = Wallet.generate_work_rpc(public_key, self.rpc_network)

        # Create the block
        block = {
            "type": "state",
            "account": account,
            "previous": previous,
            "representative": representative,
            "balance": received_amount,
            "link": send_block_hash,
            "signature": "",
            "work": work
        }

        # Add the signature
        block["signature"] = Wallet.sign_block(block, private_key)

        # Process the block
        response = self.process(block, "open")
        return response
