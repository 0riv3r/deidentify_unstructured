'''
encryption_types.py

enum to represent cipher types:
1) BLOCK
2) STREAM

'''

from enum import Enum

class EncryptionType(Enum):
    BLOCK = 1
    STREAM = 2