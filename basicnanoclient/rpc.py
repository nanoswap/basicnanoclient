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

    def key_expand(self: Self, key: str) -> str:
        """Expand a Nano private key to a public key.

        Args:
            key (str): The private key to expand.

        Returns:
            str: The public key.
        """
        return session.post(self.rpc_network, json={
            "action": "key_expand",
            "key": key
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
        print(block)
        block_json = json.dumps(block)
        request = {
            "action": "process",
            "json_block": "true",
            "sub_type": sub_type,
            "block": block
        }
        print(request)
        response = requests.post(self.rpc_network, json=request)
        return response.json()

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
        representative = account #"nano_1jg8zygjg3pp5w644emqcbmjqpnzmubfni3kfe1s8pooeuxsw49fdq1mco9j"  # "nano_1qzjqcpmwh9osbht7mub5jhyyfb69pyddjk9my6nn8efjxqeu85c44py6zff"  # Nano foundation representative

        # Generate work using public key
        if work is None:
            work = Wallet.generate_work_rpc(public_key)
            print("Work: " + work)

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
        block["signature"] = Wallet.sign_block_rpc(block, private_key)

        # Process the block
        response = self.process(block, "open")
        return response
