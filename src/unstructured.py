'''
unstructured/unstructured.py

manage the de-identify and re-identify of un-structured data
Locating the PII items in the unstructured text is done using AWS Comprehend.


The assumption for this POC is that our data analysis is in some structured data
therefore we don't have in this POC re-identifying of unstructured data, 
so the re-identify methods in this 'unstructured.py' file are not as complete as with the ones
in the 'structured.py' file.
If this is required I have this code elsewhere.

If you need help with this please contact me: ofer.rivlin@cyberark.com
'''

import json
from datetime import date

from de_identify import Deidentify
from comprehend import Comprehend


class Unstructured:

    def __init__(self, 
                 s3_client, 
                 bucket_source, 
                 bucket_deidentified,
                 list_sensitive_types,
                 bucket_analyzed,
                 bucket_reidentified) -> None:
        '''
        :param str bucket_source: the source data s3 bucket
        :param str bucket_deidentified: the s3 bucket where the de-identified data should be stored 
        :param list list_sensitive_types: the pii data types we want/expect to find (e.g. 'Email', 'Name', etc.)
        :param str bucket_analyzed: the s3 bucket where the DE-identified analysis results data should be stored
        :param str bucket_reidentified: the s3 bucket where the RE-identified analysis results data should be stored
        '''
        self.s3_client = s3_client
        self.bucket_source = bucket_source
        self.bucket_deidentified = bucket_deidentified
        self.list_sensitive_types = list_sensitive_types
        self.bucket_analyzed = bucket_analyzed
        self.bucket_reidentified = bucket_reidentified

    
    def _bucket_list_folders(self):
        list_objects = self.s3_client.list_objects_v2(Bucket=self.bucket_source, 
                                                      Prefix='', 
                                                      Delimiter='/')
        for content in list_objects.get('CommonPrefixes', []):
            yield content.get('Prefix')

    def deidentify(self, encryption_type, gen_key, header):
        '''
        :param EncryptionType enum encryption_type: EncryptionType.BLOCK / EncryptionType.STREAM
        :param bool gen_key: should we generate a new key? If True a new key will be generated and overwrite the previous key
        :param byte header: the header bytes token
        '''

        '''
        1. create a list of all the first level folders in the source bucket
        2. read each file in the bucket
        3. deidentify each file
        4. save every deidentified file with the same path and name in the deidentified bucket
        '''
        deidentify = Deidentify()
        comprehend = Comprehend(list_sensitive_types=self.list_sensitive_types)

        if gen_key:
            # generate a new cryptography key - this overwrites the previous key!
            deidentify.save_key_to_file()
        deidentify.read_key_from_file()

        for prefix in self._bucket_list_folders():
            # get the files under each folder
            list_obj_files = self.s3_client.list_objects_v2(Bucket=self.bucket_source, 
                                                            Prefix=prefix)
            # read each file
            for f in list_obj_files.get('Contents'):
                file_path = f.get('Key')
                obj_file = self.s3_client.get_object(Bucket=self.bucket_source, 
                                                Key=file_path)
                # the file content in text
                text_source = obj_file['Body'].read().decode('utf-8')

                if 0 == len(text_source):
                    # empty file
                    continue

                dict_pii_report = comprehend.detect_pii_entities(text_source)
                '''
                dict --> {data-type: [list of this data-type findings in the text]}
                '''

                deidentify_text = deidentify.deidentify(raw_text=text_source, 
                                                        dict_sensitive=dict_pii_report, 
                                                        encryption_type=encryption_type,
                                                        header=header)

                # Convert the string content to bytes
                binary_json_content = json.dumps(deidentify_text).encode()   
                # rename the file to have '_deidentified.txt' ending
                file_path_deidentified = file_path.replace('.txt', '_deidentified.txt') 
                # save the deidentified file in s3  
                self.s3_client.put_object(Body=binary_json_content, Bucket=self.bucket_deidentified, Key=file_path_deidentified)
                print('\nfile: {}'.format(file_path))
