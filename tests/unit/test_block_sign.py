import unittest

from basicnanoclient.rpc import RPC


class TestBlockSign(unittest.TestCase):

    def setUp(self):
        self.client = RPC("http://127.0.0.1:17076")

        # Sample data for testing
        self.public_key = "4A8E4F7D26C3124A9E7F1EC60EAD7E5D6BDA4D6B7359737BAECFDD5D504ACB42"
        self.previous = "0000000000000000000000000000000000000000000000000000000000000000"
        self.representative = "A0599F9261E9AB882830DD7AC53C8BA8A9EE4A1D171E8EB12A531E3B47DC64CA"
        self.balance = "00000000000000000000000000000000"
        self.link = "E529CB7BD70B8C1E5A7C94B1E79DB8A9277F2DBA9C3F3C7FF6078C21278D3AC2"
        self.private_key = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"

        # Expected outputs
        self.expected_hash = "64e54bea4b5796b40c2d14a4840dfeea775a93d1a61d686751260cd45ad851af"
        self.expected_signature = "9d73f8d326ebaedc17312b060d4f2028ea1da4aa43a26687d3a3885eb7fb32b39051952bb38e863a7e64d4e211e5f9b229eb9b2443ddfacb9ec8a99928ce1409"

    def test_calculate_block_hash(self):
        block_hash = self.client._calculate_block_hash(
            self.public_key,
            self.previous,
            self.representative,
            self.balance,
            self.link
        ).hex()

        self.assertEqual(block_hash, self.expected_hash, f"Expected {self.expected_hash} but got {block_hash}")

    def test_sign_block_hash(self):
        signature = self.client._sign_block_hash(self.expected_hash, self.private_key)
        self.assertEqual(signature, self.expected_signature, f"Expected {self.expected_signature} but got {signature}")

if __name__ == "__main__":
    unittest.main()
