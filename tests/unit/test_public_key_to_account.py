import unittest
import binascii
from hashlib import blake2b

from basicnanoclient.nano import BasicNanoClient

class TestBasicNanoClient(unittest.TestCase):
    def setUp(self):
        """Setup the test client."""
        self.client = BasicNanoClient("http://127.0.0.1:17076")

    def test_encode_nano_base32(self):
        """Test encode_nano_base32 method."""
        data = b'I\x10\xd0 i'
        encoded = self.client.encode_nano_base32(data)
        expected_encoded = 'b6af1a5b'
        self.assertEqual(encoded, expected_encoded)

    def test_decode_nano_base32(self):
        """Test decode_nano_base32 method."""
        encoded = 'b6af1a5b'
        decoded = self.client.decode_nano_base32(encoded)
        expected_decoded = b'I\x10\xd0 i'
        self.assertEqual(decoded, expected_decoded)

    def test_public_key_to_account(self):
        """Test public_key_to_account method."""
        public_key = '4C9EF365D1F62A36BC0C352B74DB9619B7D1E5745263D0A2C9C9053D9F07A0FF'
        account = self.client.public_key_to_account(public_key)
        # Compute the expected account manually
        public_key_bytes = binascii.unhexlify(public_key)
        account_prefix = 'nano_'
        account_key = self.client.encode_nano_base32(public_key_bytes)
        checksum = blake2b(public_key_bytes, digest_size=5).digest()
        checksum = self.client.encode_nano_base32(checksum[::-1])
        expected_account = account_prefix + account_key + checksum
        self.assertEqual(account, expected_account)

if __name__ == '__main__':
    unittest.main()
