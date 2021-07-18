'''
headers.py

manage the cryptography ciphers' headers
'''

from base64 import b64encode
from base64 import b64decode
import json
from Crypto.Random import get_random_bytes

class Headers:

    headers_file_path = "headers.json"

    def __init__(self) -> None:
        pass

    def _get_new_token(self):
        '''
        Generate cryptography safe random bytes using Crypto.Random library
        https://pycryptodome.readthedocs.io/en/latest/src/random/random.html
        '''
        token = get_random_bytes(16)

        # decode the binary token and encode into base-64
        return b64encode(token).decode('utf-8')


    def add_new_header(self, granular_type, header, headers_file=headers_file_path):
        new_header = {header: self._get_new_token()}
        with open(headers_file,'r+') as file:
            json_headers = json.load(file)

            # make sure the list has unique keys
            exists = False
            for v_header in json_headers[granular_type]:
                for k, v in v_header.items():
                    if(k == header):
                        exists = True
                        break

            if exists == False:
                # this is a new header key
                json_headers[granular_type].append(new_header)
                # Sets file's current position at offset.
                file.seek(0)
                json.dump(json_headers, file, indent = 4)


    def get_header_bytes_token(self, granular_type, header, headers_file=headers_file_path):
        '''
        return the bytes array header token
        '''
        with open(headers_file,'r') as file:
            json_headers = json.load(file)
            b64_token = None
            for v_header in json_headers[granular_type]:
                for k, v in v_header.items():
                    if(k == header):
                        b64_token = v
                        break

        return b64decode(b64_token)
  
