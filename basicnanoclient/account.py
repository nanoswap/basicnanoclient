__package__ = "basicnanoclient"

import time
from utils import nano


class Account():
    """An object representing an Account.

    ```py
    >>> from basicnanoclient.nano import Account
    >>> account1 = Account(key = "blah blah blah")
    >>> account2 = Account(key = "blah blah blah 2")
    >>> account1.send(account2.account, 1)
    >>> account2.receivable()
    ```
    """
    
    def __init__(self, key: str) -> None:
        """Constructor."""
        # add key data
        self.key = key
        key_expand_response = nano.key_expand(key)
        self.account = key_expand_response['account']
        
        # create the wallet
        wallet_create_response = nano.wallet_create(self.key)
        print(wallet_create_response)
        assert 'error' not in wallet_create_response
        self.wallet = wallet_create_response['wallet']
        
        # create the account
        accounts_create_response = nano.accounts_create(self.wallet)
        assert 'error' not in accounts_create_response

    def send(self, destination: str, amount: str) -> None:
        """Send <amount> of raw xno from self.account to <destination>."""
        assert self.balance(self.wallet) >= amount
        nano.send(self.wallet, self.account, destination, amount)

    async def receivable(self) -> None:
        """Receive any pending transactions to self."""
        while True:
            receivable_response = nano.receivable(self.account)
            print(receivable_response)
            
            blocks = receivable_response["blocks"]
            print(blocks)
            if blocks:
                block = list(blocks.keys())[0]
                block = nano.process(block)  # add the block
                break
            
            time.sleep(10)

        nano.receive(self.wallet, self.account, block)

    def balance(self, wallet: str) -> int:
        """Get the account balance in raw xno."""
        account_info_response = nano.account_info(wallet)
        assert 'error' not in account_info_response
        return account_info_response['balance']
