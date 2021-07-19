'''
unstructured/key.py

manage the encryption key

In the poc/demo the key is saved on a cleartext local file
This is not a good practice, and should be done only if we really know what we are doing!

There are many secure ways for saving the key, the choice depends on the environment and situation.
On AWS we can encrypt the key using KMS and save the encrypted key,
this way of working with a cryptographic key is called with terms like: 
key-wrapping, KeK (key encryption key) or envelope-encryption
'''

# key.py

# https://pycryptodome.readthedocs.io/en/latest/src/random/random.html
from Crypto.Random import get_random_bytes


class Key:

    key_file_name = 'key.bin' # the file where the key is saved

    def __init__(self):
        self._key = None

    def generate_key(self):
        '''
        Generate cryptography safe random bytes using Crypto.Random library
        https://pycryptodome.readthedocs.io/en/latest/src/random/random.html
        '''
        self._key = get_random_bytes(32) # key length. 16 bytes == 128 bits, 32 bytes == 256 bits
        return self._key

    @property
    def key(self):
        return self._key

    def save_key_to_file(self, file_name=key_file_name):
        '''
        This action overwrites the previous key!
        '''
        f = open(file_name, "wb")
        f.write(self._key)
        f.close()
        
    def read_key_from_file(self, file_name=key_file_name):
        f = open(file_name, "rb")
        self._key = f.read()
        f.close()
        return self._key