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

    def test_generate_seed(self):
        """Test generate_seed method."""
        seed = self.client.generate_seed()
        self.assertEqual(len(seed), 64)  # Seed should be 64 characters long
        self.assertTrue(all(c in '0123456789abcdef' for c in seed))  # Seed should be hexadecimal

    def test_key_expand(self):
        """Test key_expand method."""
        private_key = '3da2a4ca4580fa8e4afc6d541d583f36733a0e4cf21bef36d1017dc387793423'
        result = self.client.key_expand(private_key)
        self.assertIsInstance(result, dict)
        self.assertIn('public', result)
        self.assertIn('account', result)
        self.assertEqual(len(result['public']), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in result['public']))
        self.assertTrue(result['account'].startswith('nano_'))

    def test_public_key_to_account(self):
        """Test public_key_to_account method."""
        public_key = '2177bdc9249274407582fbc0ef986edfbfb336c12aadbbdf14f342d9cb008c6e'
        account_address = self.client.public_key_to_account(public_key)
        self.assertTrue(account_address.startswith('nano_'))
        self.assertEqual(len(account_address), 65)

    def test_derive_account(self):
        """Test derive_account method."""
        seed = '7df6c82842d1ed8ad67cb625f2f7095e0227044f28526989bd8c11ab4ff20294'
        index = 0
        result = self.client.derive_account(seed, index)
        self.assertIsInstance(result, dict)
        self.assertIn('private', result)
        self.assertIn('public', result)
        self.assertIn('account', result)
        self.assertEqual(len(result['private']), 64)
        self.assertEqual(len(result['public']), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in result['private']))
        self.assertTrue(all(c in '0123456789abcdef' for c in result['public']))
        self.assertTrue(result['account'].startswith('nano_'))

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
