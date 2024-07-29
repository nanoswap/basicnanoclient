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

    # def receive(self: Self, hash: str, private_key: str) -> dict:
    #     """Receive a pending Nano transaction.

    #     Args:
    #         hash (str): The hash of the pending transaction.
    #         private_key (str): The private key of the receiving account.

    #     Returns:
    #         dict: A dictionary containing information about the transaction.
    #     """
    #     # Retrieve the block info
    #     block_info = self.block_info(hash)

    #     # Ensure this is the first block for the receiving account
    #     previous = 

    def _calculate_block_hash(self: Self, public_key: str, previous: str, representative: str, balance: str, link: str) -> bytes:
        """Calculate the hash of a Nano block.

        Args:
            public_key (str): The public key of the account.
            previous (str): The previous block hash.
            representative (str): The representative account.
            balance (str): The balance of the account.
            link (str): The link hash.

        Returns:
            bytes: The hash of the block.
        """
        bh = blake2b(digest_size=32)
        bh.update(BitArray(hex='0000000000000000000000000000000000000000000000000000000000000006').bytes)
        bh.update(BitArray(hex=public_key).bytes)
        bh.update(BitArray(hex=previous).bytes)
        bh.update(BitArray(hex=representative).bytes)
        bh.update(BitArray(hex=balance).bytes)
        bh.update(BitArray(hex=link).bytes)
        return bh.digest()

    def _sign_block_hash(self: Self, block_hash: str, private_key: str, public_key: str) -> str:
        """Sign a block hash.

        Args:
            block_hash (str): The block hash to sign.
            private_key (str): The private key of the account.
            public_key (str): The public key of the account.

        Returns:
            str: The signature of the block hash.
        """
        sk = ed25519.SigningKey(binascii.unhexlify(private_key) + binascii.unhexlify(public_key))
        sig = sk.sign(block_hash)
        return binascii.hexlify(sig).decode()

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

        # Convert representative to public key
        representative_key = Utils.nano_address_to_public_key(representative)

        # # Use received_amount as the new balance since it's the first block
        balance_hex = hex(int(received_amount))[2:].upper().rjust(32, '0')

        # Generate work using public key
        if work is None:
            work = Wallet.generate_work_rpc(public_key)
            print("Work: " + work)

        # Calculate the signature
        new_block_hash = self._calculate_block_hash(public_key, previous, representative_key, balance_hex, send_block_hash)
        print(binascii.hexlify(new_block_hash).decode())
        new_block_hash = binascii.unhexlify("59126B47261A5C7832197CB7393D7B1B87648E8B1863CB84F12263B4E8C947A9")
        signature = self._sign_block_hash(new_block_hash, private_key, public_key)

        # Create the block
        block = {
            "type": "state",
            "account": account,
            "previous": previous,
            "representative": representative,
            "balance": received_amount,
            "link": send_block_hash,
            "signature": signature,
            "work": work
        }

        print(block)
        # Process the block
        # response = self.process(block, "open")
        # return response

    # def receive_first(self: Self, block_hash: str, private_key: str, account: str) -> dict:
    #     """Receive the first block for an account.

    #     Args:
    #         block_hash (str): The block hash to receive (from `receivable`)
    #         private_key (str): The private key of the receiving account
    #         account (str): The account to receive the block

    #     Returns:
    #         dict: A dictionary containing information about the transaction.
    #     """

    #     # Open the account
    #     self.open_account(account, private_key, block_hash)

    #     # Retrieve the block info

    #     block_info = self.block_info(block_hash)

    #     # Ensure this is the first block for the receiving account
    #     previous = '0000000000000000000000000000000000000000000000000000000000000000'

    #     # response = self.sign_and_process(
    #     #     previous=previous,
    #     #     account=block_info['contents']['link_as_account'],
    #     #     representative=block_info['contents']['representative'],
    #     #     balance=block_info['amount'],
    #     #     link=block_hash,
    #     #     key=private_key,
    #     #     subtype="open"
    #     # )

    #     # Create the block
    #     block = Wallet.block_create(
    #         previous,
    #         account,
    #         representative,
    #         balance,
    #         link,
    #         key
    #     )

    #     # Process the block
    #     response = self.process(block, "open")
    #     return response
