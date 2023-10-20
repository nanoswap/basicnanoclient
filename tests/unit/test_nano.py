import unittest
from typing import Self
from unittest.mock import Mock, patch

from basicnanoclient.nano import BasicNanoClient

import requests


class TestBasicNanoClient(unittest.TestCase):
    """Test the BasicNanoClient class."""

    def setUp(self: Self) -> None:
        """Setup the test client and mock response."""
        self.client = BasicNanoClient("http://127.0.0.1:17076")
        self.mock_response = Mock()

    @patch('requests.Session.post')
    def test_key_expand(self: Self, mock_post: Mock) -> None:
        """Test the key_expand method."""
        self.mock_response.json.return_value = {
            "public": "sample_public_key",
            "account": "sample_account_address"
        }
        mock_post.return_value = self.mock_response

        response = self.client.key_expand("sample_key")
        self.assertEqual(response["public"], "sample_public_key")

    @patch('requests.Session.post')
    def test_wallet_create(self: Self, mock_post: Mock) -> None:
        """Test the wallet_create method."""
        self.mock_response.json.return_value = {
            "wallet": "sample_wallet_id",
            "key": "sample_key"
        }
        mock_post.return_value = self.mock_response

        response = self.client.wallet_create("sample_key")
        self.assertEqual(response["wallet"], "sample_wallet_id")

    @patch('requests.Session.post')
    def test_accounts_create(self: Self, mock_post: Mock) -> None:
        """Test the accounts_create method."""
        self.mock_response.json.return_value = {
            "accounts": ["sample_account_1", "sample_account_2"]
        }
        mock_post.return_value = self.mock_response

        response = self.client.accounts_create("sample_wallet_id", 2)
        self.assertEqual(len(response["accounts"]), 2)

    @patch('requests.Session.post')
    def test_receive(self: Self, mock_post: Mock) -> None:
        """Test the receive method."""
        self.mock_response.json.return_value = {
            "block": "sample_block"
        }
        mock_post.return_value = self.mock_response

        response = self.client.receive(
            "sample_wallet",
            "sample_account",
            "sample_block"
        )
        self.assertEqual(response["block"], "sample_block")

    @patch('requests.Session.post')
    def test_account_info(self: Self, mock_post: Mock) -> None:
        """Test the account_info method."""
        self.mock_response.json.return_value = {
            "frontier": "sample_frontier",
            "balance": "sample_balance",
            "representative": "sample_representative",
            "block_count": "sample_block_count"
        }
        mock_post.return_value = self.mock_response

        response = self.client.account_info("sample_account")
        self.assertEqual(response["frontier"], "sample_frontier")

    @patch('requests.Session.post')
    def test_wallet_info(self: Self, mock_post: Mock) -> None:
        """Test the wallet_info method."""
        self.mock_response.json.return_value = {
            "wallet_id": "sample_wallet_id",
            "balance": "sample_balance"
        }
        mock_post.return_value = self.mock_response

        response = self.client.wallet_info("sample_wallet")
        self.assertEqual(response["wallet_id"], "sample_wallet_id")

    @patch('requests.Session.post')
    def test_ledger(self: Self, mock_post: Mock) -> None:
        """Test the ledger method."""
        self.mock_response.json.return_value = {
            "history": ["sample_tx_1", "sample_tx_2"]
        }
        mock_post.return_value = self.mock_response

        response = self.client.ledger("sample_account", 2)
        self.assertEqual(len(response["history"]), 2)

    @patch('requests.post')
    def test_process(self: Self, mock_post: Mock) -> None:
        """Test the process method."""
        self.mock_response.json.return_value = {
            "hash": "sample_hash"
        }
        mock_post.return_value = self.mock_response

        response = self.client.process("sample_block")
        self.assertEqual(response["hash"], "sample_hash")

    @patch('requests.post')
    def test_sign_and_send(self: Self, mock_post: Mock) -> None:
        """Test the sign_and_send method."""
        self.mock_response.json.return_value = {
            "hash": "sample_hash"
        }
        mock_post.return_value = self.mock_response

        response = self.client.sign_and_send(
            "sample_previous",
            "sample_account",
            "sample_representative",
            "sample_balance",
            "sample_link",
            "sample_key"
        )
        self.assertEqual(response["hash"], "sample_hash")

    @patch.object(BasicNanoClient, 'sign_and_send')
    @patch.object(BasicNanoClient, 'account_info')
    @patch.object(BasicNanoClient, 'wallet_info')
    def test_send(
            self: Self,
            mock_wallet_info: Mock,
            mock_account_info: Mock,
            mock_sign_and_send: Mock) -> None:
        """Test the send method."""
        # Mock wallet_info response
        mock_wallet_info.return_value = {
            "key": "sample_wallet_private_key"
        }

        # Mock account_info response
        mock_account_info.return_value = {
            "frontier": "sample_frontier",
            "representative": "sample_representative",
            "balance": "1000"  # Some sample balance
        }

        # Mock sign_and_send response
        mock_sign_and_send.return_value = {
            "hash": "sample_transaction_hash"
        }

        # Call the send method
        response = self.client.send(
            "sample_wallet",
            "sample_source",
            "sample_destination",
            100,  # some sample amount less than the balance
            "sample_key"
        )

        # Check the response
        self.assertEqual(response["hash"], "sample_transaction_hash")

        # Optionally: Check if methods were called with correct arguments
        mock_wallet_info.assert_called_once_with("sample_wallet")
        mock_account_info.assert_called_once_with("sample_source")
        mock_sign_and_send.assert_called_once()

    @patch('requests.Session.post')
    def test_account_info_request_exception(
            self: Self,
            mock_post: Mock) -> None:
        """Test the account_info method raises a RequestException."""
        mock_post.side_effect = requests.exceptions.RequestException(
            "Mocked exception"
        )
        with self.assertRaises(requests.exceptions.RequestException):
            self.client.account_info("sample_account")

    @patch('requests.Session.post')
    def test_key_expand_request_exception(self: Self, mock_post: Mock) -> None:
        """Test the key_expand method raises a RequestException."""
        mock_post.side_effect = requests.exceptions.RequestException(
            "Mocked exception"
        )
        with self.assertRaises(requests.exceptions.RequestException):
            self.client.key_expand("sample_key")


if __name__ == "__main__":
    unittest.main()
