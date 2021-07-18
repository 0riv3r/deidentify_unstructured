'''
re_identify.py

please note: this is not completely done yet,
The decrypt of the stream cipher is missing the part of verifying the hmac!!

'''

import re
import json
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Hash import Poly1305

from key import Key
from encryption_types import EncryptionType
from decryption_exception import DecryptionException


class Reidentify:

    def __init__(self):
        self._key = None
        self._deidentifed_data = None
        self._reidentifed_data = None
        self._key_file_name = 'key.bin' # the key (only in the demo)
        self.obj_key = Key()

    def read_key_from_file(self):
        self._key = self.obj_key.read_key_from_file()

    def _decrypt_block_cipher(self, dict_deidentified_text):
        '''
        AES Block cipher decryption
        '''
        reidentified_text = ''

        try:
            json_k = [ 'header', 'ciphertext', 'tag' ]
            # dict_deidentified_text is encoded with base-64
            jv = {k:b64decode(dict_deidentified_text[k]) for k in json_k}

            cipher = AES.new(self._key, AES.MODE_SIV)
            cipher.update(jv['header'])
            plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
            reidentified_text = plaintext.decode('utf-8')
        except KeyError:
            raise DecryptionException("KeyError, decryption aborted!")
        except ValueError:
            raise DecryptionException("MAC verification failed, decryption aborted!")
        
        return reidentified_text


    def _decrypt_stream_cipher(self, dict_deidentified_text):
        '''
        ChaCha20 steram cipher decryption
        missing the verification of the hmac!!
        '''
        reidentified_text = ''

        try:
            json_k = [ 'ciphertext', 'tag' ]
            # dict_deidentified_text is encoded with base-64
            jv = {k:b64decode(dict_deidentified_text[k]) for k in json_k}

            cipher = ChaCha20.new(key=self._key, nonce=jv['tag'])
            plaintext = cipher.decrypt(jv['ciphertext'])
            reidentified_text = plaintext.decode('utf-8')
        except KeyError:
            raise DecryptionException("KeyError, decryption aborted!")
        except ValueError:
            raise DecryptionException("MAC verification failed, decryption aborted!")
        
        return reidentified_text


    def reidentify(self, json_deidentified, list_deidentified_fields, encryption_type, header_token):
        '''
        json_deidentified: the deidentified json text
        list_deidentified_fields: the deidentified types (e.g. email, name, etc.)
        '''

        '''
        1. get all the deidentified unique instances in text
        2. parse the items
        3. re-identify each de-identified key
        4. re-create the original file using the dictionary
        '''

        dict_reidentified = {}
        try:
            for field in list_deidentified_fields:
                for key in json_deidentified.keys():
                    if key.startswith(field):
                        # 1. extract the deidentified text
                        # example: "email(77)_5x+2UuW0RxPbR/opWDKYcfgN6FreW6zkMIgujUNHnx0X&NTI5ODA0YzNkZjg5MDU0ZjUwMzc5ZTQy"
                        number_of_chars = int(re.search('\(([0-9]+)\)', key).group(1)) # group(1) numbers only
                        str_number = re.search('\(([0-9]+)\)', key).group(0)  # group(0) numbers include the parenthesis
                        start_index = len(field) + len(str_number) + 1  # the 1 is for the underscore
                        deidentified_text = key[start_index:(start_index + number_of_chars)]

                        # 2. parse the deidentified text to ciphertext + tag
                        # 3. get the reidentified text
                        list_deidentified_item = list(deidentified_text.split("&"))

                        if EncryptionType.BLOCK == encryption_type:
                            reidentified_text = self._decrypt_block_cipher({# 'header': list_deidentified_item[0],
                                                                            'header': header_token,
                                                                            'ciphertext': list_deidentified_item[0], 
                                                                            'tag': list_deidentified_item[1]})
                        elif EncryptionType.STREAM == encryption_type:
                            reidentified_text = self._decrypt_stream_cipher({# 'header': list_deidentified_item[0],
                                                                            'header': header_token,
                                                                            'ciphertext': list_deidentified_item[0], 
                                                                            'tag': list_deidentified_item[1]})

                        dict_reidentified.update({reidentified_text: json_deidentified[key]})

        except AttributeError:
            # not found
            print('not found')

        return dict_reidentified

        





