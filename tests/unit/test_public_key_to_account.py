import unittest
import binascii
from hashlib import blake2b

from basicnanoclient.utils import Utils

class TestBasicNanoClient(unittest.TestCase):
    def test_encode_nano_base32(self):
        """Test encode_nano_base32 method."""
        data = b'I\x10\xd0 i'
        encoded = Utils.encode_nano_base32(data)
        expected_encoded = 'b6af1a5b'
        self.assertEqual(encoded, expected_encoded)

    def test_decode_nano_base32(self):
        """Test decode_nano_base32 method."""
        encoded = 'b6af1a5b'
        decoded = Utils.decode_nano_base32(encoded)
        expected_decoded = b'I\x10\xd0 i'
        self.assertEqual(decoded, expected_decoded)

if __name__ == '__main__':
    unittest.main()
