import unittest
from typing import Self
from unittest.mock import Mock, patch

from basicnanoclient.rpc import RPC

import requests


class TestBasicNanoClient(unittest.TestCase):
    """Test the BasicNanoClient class."""

    def setUp(self: Self) -> None:
        """Setup the test client and mock response."""
        self.client = RPC("http://127.0.0.1:17076")
        self.mock_response = Mock()

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

if __name__ == "__main__":
    unittest.main()
