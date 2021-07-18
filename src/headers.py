'''
headers.py

manage the cryptography ciphers' headers

headers are granularity types with their cryptography generated tokens
{header-type: token}
{"jul21": "daL7iNxi5akLB1b0rvRwqg=="}
'''

from base64 import b64encode
from base64 import b64decode
import json
from Crypto.Random import get_random_bytes

class Headers:

    headers_file_path = "headers.json"

    def __init__(self, headers_file_path=headers_file_path) -> None:
        self.headers_file_path = headers_file_path

    def _get_new_token(self):
        '''
        Generate cryptography safe random bytes using Crypto.Random library
        https://pycryptodome.readthedocs.io/en/latest/src/random/random.html
        '''
        token = get_random_bytes(16)

        # decode the binary token and encode into base-64
        return b64encode(token).decode('utf-8')


    def add_new_header(self, granular_type, header):
        '''
        adds a new header dict to the headers json file
        granular_type: the granular type, i.e. 'months'
        header: the granular header, i.e. 'jul21'
        '''
        new_header = {header: self._get_new_token()}
        with open(self.headers_file_path,'r+') as file:
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


    def get_header_bytes_token(self, granular_type, header):
        '''
        return the bytes array header token
        granular_type: the granular type, i.e. 'months'
        header: the granular header, i.e. 'jul21'
        '''
        with open(self.headers_file_path,'r') as file:
            json_headers = json.load(file)
            b64_token = None
            for v_header in json_headers[granular_type]:
                for k, v in v_header.items():
                    if(k == header):
                        b64_token = v
                        break

        return b64decode(b64_token)
  
