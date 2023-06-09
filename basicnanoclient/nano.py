__package__ = "basicnanoclient"

import subprocess
import uuid
from typing import Any, Dict

import requests

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

    def __init__(self, rpc_network: str) -> None:
        """Constructor."""
        self.rpc_network = rpc_network

    def generate_private_key(self) -> str:
        """Generate a private key using the /dev/urandom command.

        Returns:
            The generated key
        """
        command = "LC_ALL=C cat /dev/urandom | LC_ALL=C tr -dc '0-9A-F' | LC_ALL=C head -c${1:-64}"  # noqa: E501
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            universal_newlines=True
        )
        return process.stdout.read()

    def key_expand(self, key: str) -> Dict[str, Any]:
        """Expands a given Nano private key into a public key
        and account address.

        Args:
            key (str): A 64-character hexadecimal string representing the
                Nano private key.

        Returns:
            A dictionary with keys 'public' and 'account', where 'public' is a
            64-character hexadecimal string representing
            the Nano public key and 'account' is the Nano account address.

        Raises:
            requests.exceptions.RequestException: If there is an error sending
                the RPC request.
        """
        return session.post(self.rpc_network, json={
            "action": "key_expand",
            "key": key
        }).json()

    def wallet_create(self, key: str) -> Dict[str, Any]:
        """Creates a new Nano wallet with a given seed (private key).

        Args:
            key (str): A 64-character hexadecimal string representing the
                Nano private key.

        Returns:
            A dictionary with keys 'wallet' and 'key', where 'wallet' is the
            Nano wallet ID and 'key' is the seed (private key)
            used to create the wallet.

        Raises:
            requests.exceptions.RequestException: due to the RPC request.
        """
        return session.post(self.rpc_network, json={
            "action": "wallet_create",
            "seed": key,
        }).json()

    def accounts_create(self, wallet: str, count: int = 1) -> Dict[str, Any]:
        """Creates a specified number of new Nano accounts in a given wallet.

        Args:
            wallet (str): The Nano wallet ID.
            count (int): The number of accounts to create in the wallet.
                Default is 1.

        Returns:
            A dictionary with key 'accounts',
                where the value is a list of Nano account addresses.

        Raises:
            requests.exceptions.RequestException: due to the RPC request.
        """
        return session.post(self.rpc_network, json={
            "action": "accounts_create",
            "wallet": wallet,
            "count": count
        }).json()

    def receive(self, wallet: str, account: str, block: str) -> Dict[str, Any]:
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

    def account_info(self, account: str) -> Dict[str, Any]:
        """Retrieves information about a Nano account.

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

    def wallet_info(self, wallet: str) -> Dict[str, Any]:
        """Retrieves information about a Nano wallet.

        Parameters:
            wallet (str): The Nano wallet address.

        Returns:
            A dictionary containing information about the Nano wallet.
        """
        return session.post(self.rpc_network, json={
            "action": "wallet_info",
            "wallet": wallet
        }).json()

    def ledger(self, account: str, count: int) -> Dict[str, Any]:
        """Retrieves the transaction history for a Nano account.

        Parameters:
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

    def wallet_history(self, wallet: str) -> Dict[str, Any]:
        """Retrieves the transaction history for a Nano wallet.

        Parameters:
            wallet (str): The Nano wallet address.

        Returns:
            A dictionary containing the transaction history
                for the Nano wallet.
        """
        return session.post(self.rpc_network, json={
            "action": "wallet_history",
            "wallet": wallet
        }).json()

    def account_list(self, wallet: str) -> Dict[str, Any]:
        """Retrieves a list of Nano accounts associated with a wallet.

        Parameters:
            wallet (str): The Nano wallet address.

        Returns:
            A dictionary containing a list of Nano accounts
            associated with the wallet.
        """
        return session.post(self.rpc_network, json={
            "action": "account_list",
            "wallet": wallet
        }).json()

    def send(self, wallet: str, source: str, destination: str, amount: int) -> Dict[str, Any]:  # noqa: E501
        """Sends a specified amount of Nano from one account to another.

        Parameters:
            wallet (str): The Nano wallet address.
            source (str): The Nano account address to send from.
            destination (str): The Nano account address to send to.
            amount (int): The amount of Nano to send in raw units.

        Returns:
            A dictionary containing information about the transaction.
        """
        return session.post(self.rpc_network, json={
            "action": "send",
            "wallet": wallet,
            "source": source,
            "destination": destination,
            "amount": str(amount),
            "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, 'nanoswap.finance'))
        }).json()

    def receivable(
            self,
            account: str,
            count: int = 1,
            threshold: int = 1000000000000000000000000) -> Dict[str, Any]:
        """Retrieves a list of pending Nano transactions for an account.

        Parameters:
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

    def block_create(
            self,
            previous: str,
            account: str,
            representative: str,
            balance: str,
            link: str,
            key: str) -> dict:
        """
        Creates a new block.

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
        return session.post(self.rpc_network, json={
            "action": "block_create",
            "json_block": "true",
            "type": "state",
            "previous": previous,
            "account": account,
            "representative": representative,
            "balance": balance,
            "link": link,
            "key": key
        }).json()

    def process(self, block: str) -> dict:
        """ Processes a block.

        Args:
            block (str): The block to be processed.

        Returns:
            dict: A dictionary containing information about the block processing.
        """
        response = requests.post(self.rpc_network, json={
            "action": "process",
            "block": block
        })
        return response.json()
