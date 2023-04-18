import subprocess
from src.utils import nano

def test_key_expand():
    key = '123456789ABCDEF0123456789ABCDEF0'
    result = nano.key_expand(key)
    assert 'public' in result.keys() and len(result['public'].strip()) == 64
    assert 'private' in result.keys() and len(result['private'].strip()) == 64
    assert 'account' in result.keys() and len(result['account'].strip()) == 65
