__package__ = "basicnanoclient"

from typing import Any, Dict, Self

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

    def __init__(self: Self, rpc_network: str) -> None:
        """Constructor."""
        self.rpc_network = rpc_network

    def key_expand(self: Self, key: str) -> Dict[str, Any]:
        """Expand a private key into a public key and account address.

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

    def wallet_create(self: Self, key: str) -> Dict[str, Any]:
        """Create a new Nano wallet with a given seed (private key).

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

    def accounts_create(
            self: Self,
            wallet: str,
            count: int = 1) -> Dict[str, Any]:
        """Create a specified number of new Nano accounts in a given wallet.

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

    def process(self: Self, block: str) -> dict:
        """Process a block.

        Args:
            block (str): The block to be processed.

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
        block_hash = block.get('hash')

        # Process the block
        response = self.process(block_hash)

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
