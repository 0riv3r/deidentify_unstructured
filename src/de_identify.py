'''
unstructured/de_identify.py

perforoms de-identifying using block and stream ciphers

At this point the solution of using the header for granularity of data types
works only with Block cipher!
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
        self.obj_key = Key()

    def save_key_to_file(self):
        '''
        save a local file with the encryption key
        '''
        self._key = self.obj_key.generate_key()
        self.obj_key.save_key_to_file()

    def read_key_from_file(self):
        '''
        read the key from a local file
        '''
        self._key = self.obj_key.read_key_from_file()

    def _encrypt_block_cipher(self, data, header):
        '''
        Encryption using the following Block cipher:
        AES with 128 bit block size
        256 bit key length
        SIV mode
        https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html?#siv-mode
        https://datatracker.ietf.org/doc/html/rfc5297

        data: the text to be encrtypted
        header: is used here for granularity of data types

        returns the de-identified representation without the header!
        this will require us to supply the header in decrytion
        '''
        cipher = AES.new(self._key, AES.MODE_SIV)     # Mode SIV Without nonce, the encryption
                                                      # becomes deterministic
        cipher.update(header)

        '''
        encrypt_and_digest requires bytes object.
        encode return an encoded version of the string as a bytes object.
        encode defaults to 'utf-8'.
        https://docs.python.org/3/library/stdtypes.html#str.encode
        '''
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())

        json_k = [ 'header', 'ciphertext', 'tag' ]

        # decode the binary values and encode into base-64
        json_v = [ b64encode(x).decode('utf-8') for x in [header, ciphertext, tag] ]

        dict_deidentifed_data = json.loads(json.dumps(dict(zip(json_k, json_v))))
        # {"header": "aGVhZGVy", "ciphertext": "5Y1WW4za", "tag": "4xbFzP/6X49VjIBzL56NVQ=="}

        '''
        Don't keep the header token with the de-identified text!
        To get back the cleartext, we must supply the header token
        this is our mechanism for making granularity of data types that can be destroyed.
        If we deleted the header and its token from the headers database, 
        we won't be able to supply it, and we no longer 
        be able to decrypt all the data that was encrypted using this header
        '''
        # str_deidentified = dict_deidentifed_data["header"] + '&'
        str_deidentified = dict_deidentifed_data["ciphertext"] + '&'
        str_deidentified += dict_deidentifed_data["tag"]

        return str_deidentified

    def _encrypt_stream_cipher(self, data, header):
        '''
        Please note that at this point the solution of using the header for granularity of data types
        works only with Block cipher!

        Encryption using the following Stream cipher:
        ChaCha20
        256 bit key length
        with Poly1305 HMac (currently use the same encryption key, it is better to have a separate key for the HMac)
        https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20.html
        https://pycryptodome.readthedocs.io/en/latest/src/hash/poly1305.html
        https://datatracker.ietf.org/doc/html/rfc7539

        data: the text to be encrtypted
        header: currently not used in this Stream cipher, I will implement it sometimes later

        returns the de-identified representation
        '''

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

    def _create_deidentify_items_dict(self, dict_pii, encryption_type, header):
        '''
        dict_pii:
        {'email': ['itayp@researchcem.onmicrosoft.com', 'ofer@researchcem.onmicrosoft.com', 'sapir@researchcem.onmicrosoft.com'], 
        name': ['itayp', 'ofer', 'sapir']}

        encryption_type: Block or Stream

        return a dictionary: { pii-type1: {cleartext: ciphertext}, {cleartext: ciphertext}}, pii-type2: {cleartext: ciphertext} }
        '''

        dict_deidentified_items = {}
        """
        {{'email': {'gitel@researchcem.onmicrosoft.com': 'inGQ5wdpsW8CXmq6UW6eefECpFecSH1ZF9GcnNu0EwZE&D7XxHHGlrl8MYC6fdt+rSA==',  
        'kobtest100@gmail.com': 'N+jSX1ZdeklgyxS48ViLy4v5gH0=&lzUzQzSxZornYQiiRiv4Bw=='}, 
        'name': {'Carl Williams': 'bO4CviHyW5oyjo2EHA==&RFYwt8eVsQMwrzaiilnE6w==',  
        'Mary Shelly': 'j8U3/B9RDCnFAPw=&4BwsvXXqdex0wRnd1NRCtQ=='}}
        """

        for pii_type in dict_pii.keys():
            dict_pii_type = {}
            list_entities = dict_pii[pii_type]
            for entity in list_entities:
                if EncryptionType.BLOCK == encryption_type:
                    dict_pii_type.update({entity: self._encrypt_block_cipher(entity, header)})
                elif EncryptionType.STREAM == encryption_type:
                    dict_pii_type.update({entity: self._encrypt_stream_cipher(entity, header)})
            dict_deidentified_items.update({pii_type: dict_pii_type})

        return dict_deidentified_items
        


    def deidentify(self, raw_text, dict_sensitive, encryption_type, header):
        '''
        :param str raw_text: the original text
        :param dict dict_sensitive: {data-type: [list of this data-type findings in the text]}
        :param EncryptionType enum encryption_type: EncryptionType.BLOCK / EncryptionType.STREAM
        :param byte header: the header bytes token
        '''
        
        '''
        1. encrypt each pii in the dictionary
        2. replace each pii entity in the raw text with its deidentified version
        '''

        """
        {'email': {'gitel@researchcem.onmicrosoft.com': 'inGQ5wdpsW8CXmq6UW6eefECpFecSH1ZF9GcnNu0EwZE&D7XxHHGlrl8MYC6fdt+rSA==',  
        'kobtest100@gmail.com': 'N+jSX1ZdeklgyxS48ViLy4v5gH0=&lzUzQzSxZornYQiiRiv4Bw=='}, 
        'name': {'Carl Williams': 'bO4CviHyW5oyjo2EHA==&RFYwt8eVsQMwrzaiilnE6w==',  
        'Mary Shelly': 'j8U3/B9RDCnFAPw=&4BwsvXXqdex0wRnd1NRCtQ=='}}
        """
        dict_deidentified_items = self._create_deidentify_items_dict(dict_pii=dict_sensitive, 
                                                                     encryption_type=encryption_type, 
                                                                     header=header)

        '''
        go through the text and replace the original pii strings 
        with their de-identified representations
        '''
        deidentified_text = raw_text
        for pii_type in dict_deidentified_items.keys():
            dict_entities = dict_deidentified_items[pii_type]
            for original, deidentified in dict_entities.items():
                # build the de-identified string
                deidentified = pii_type + '(' + str(len(deidentified)) + ')_' + deidentified
                # replace the original string with its de-identified representation
                deidentified_text = deidentified_text.replace(original, deidentified)

        return deidentified_text
                





        