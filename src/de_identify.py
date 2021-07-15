'''
unstructured/de_identify.py

perforoms de-identifying using stream cipher

 
'''

import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Hash import Poly1305

from key import Key
from encryption_types import EncryptionType


class Deidentify:

    def __init__(self):
        self._key = None
        self._key_file_name = 'key.bin'
        # self._header = b"header"
        self.obj_key = Key()

    def save_key_to_file(self):
        self._key = self.obj_key.generate_key()
        self.obj_key.save_key_to_file()

    def read_key_from_file(self):
        self._key = self.obj_key.read_key_from_file()

    def _encrypt_block_cipher(self, data):
        cipher = AES.new(self._key, AES.MODE_SIV)     # Mode SIV Without nonce, the encryption
                                                      # becomes deterministic
        # cipher.update(self._header)

        '''
        encrypt_and_digest requires bytes object.
        encode return an encoded version of the string as a bytes object.
        encode defaults to 'utf-8'.
        https://docs.python.org/3/library/stdtypes.html#str.encode

        header is not required with structure data
        since we keep the field name in cleartext
        '''
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())

        # json_k = [ 'header', 'ciphertext', 'tag' ]
        json_k = [ 'ciphertext', 'tag' ]

        # decode the binary values and encode into base-64
        # json_v = [ b64encode(x).decode('utf-8') for x in [self._header, ciphertext, tag] ]
        json_v = [ b64encode(x).decode('utf-8') for x in [ciphertext, tag] ]

        dict_deidentifed_data = json.loads(json.dumps(dict(zip(json_k, json_v))))

        # str_deidentified = str(dict_deidentifed_data["header"]) + str('&')
        str_deidentified = dict_deidentifed_data["ciphertext"] + '&'
        str_deidentified += dict_deidentifed_data["tag"]

        return str_deidentified
                                   
        # {"header": "aGVhZGVy", "ciphertext": "5Y1WW4za", "tag": "4xbFzP/6X49VjIBzL56NVQ=="}

    def _encrypt_stream_cipher(self, data):

        hmac = Poly1305.new(key=self._key, cipher=ChaCha20)
        hmac.update(data.encode())
        hmac_nonce = hmac.nonce.hex()
        bytes_hmac_nonce = hmac_nonce.encode()

        cipher = ChaCha20.new(key=self._key, nonce=bytes_hmac_nonce) # encode the hex hmac to bytes
        ciphertext = cipher.encrypt(data.encode())

        json_k = [ 'ciphertext', 'tag' ]
        json_v = [ b64encode(x).decode('utf-8') for x in [ciphertext, bytes_hmac_nonce] ]

        dict_deidentifed_data = json.loads(json.dumps(dict(zip(json_k, json_v))))

        str_deidentified = dict_deidentifed_data["ciphertext"] + '&'
        str_deidentified += dict_deidentifed_data["tag"]

        return str_deidentified

    def _create_deidentify_items_dict(self, dict_pii, encryption_type):

        '''
        dict_pii:
        {'email': ['itayp@researchcem.onmicrosoft.com', 'ofer@researchcem.onmicrosoft.com', 'sapir@researchcem.onmicrosoft.com'], 
        name': ['itayp', 'ofer', 'sapir']}
        '''

        # {{'email': 'itayp@researchcem.onmicrosoft.com'}: xxx}
        dict_deidentified_items = {}

        for pii_type in dict_pii.keys():
            dict_pii_type = {}
            list_entities = dict_pii[pii_type]
            for entity in list_entities:
                if EncryptionType.BLOCK == encryption_type:
                    dict_pii_type.update({entity: self._encrypt_block_cipher(entity)})
                elif EncryptionType.STREAM == encryption_type:
                    dict_pii_type.update({entity: self._encrypt_stream_cipher(entity)})
            dict_deidentified_items.update({pii_type: dict_pii_type})

        return dict_deidentified_items     


    def deidentify(self, raw_text, dict_sensitive, encryption_type):
        '''
        1. encrypt each pii in the dictionary
        2. replace each pii entity in the raw text with its deidentified version
        '''
        dict_deidentified_items = self._create_deidentify_items_dict(dict_sensitive, encryption_type)

        deidentified_text = raw_text
        for pii_type in dict_deidentified_items.keys():
            dict_entities = dict_deidentified_items[pii_type]
            for original, deidentified in dict_entities.items():
                deidentified = pii_type + '(' + str(len(deidentified)) + ')_' + deidentified
                deidentified_text = deidentified_text.replace(original, deidentified)

        return deidentified_text
                





        