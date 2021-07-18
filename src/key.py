'''
unstructured/key.py

manage the encryption key
'''

# key.py

from Crypto.Random import get_random_bytes


class Key:

    key_file_name = 'key.bin'

    def __init__(self):
        self._key = None

    def generate_key(self):
        '''
        Generate cryptography safe random bytes using Crypto.Random library
        https://pycryptodome.readthedocs.io/en/latest/src/random/random.html
        '''
        self._key = get_random_bytes(16 * 2)
        return self._key

    @property
    def key(self):
        return self._key

    def save_key_to_file(self, file_name=key_file_name):
        f = open(file_name, "wb")
        f.write(self._key)
        f.close()
        
    def read_key_from_file(self, file_name=key_file_name):
        f = open(file_name, "rb")
        self._key = f.read()
        f.close()
        return self._key