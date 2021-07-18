'''
decryption_exception.py
'''

class DecryptionException(Exception):
    """
    Exception for decryption errors.

    message: the exception message
    """

    def __init__(self, message="MAC verification failed, decryption aborted!"):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f'Error: {self.message}'