'''
unstructured/unstructured.py
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

    def deidentify(self, encryption_type, gen_key):
        '''
        1. create a list of all the first level folders in the source bucket
        2. read each file in the bucket
        3. deidentify each file
        4. save every deidentified file with the same path and name in the deidentified bucket
        '''
        deidentify = Deidentify()
        comprehend = Comprehend(list_sensitive_types=self.list_sensitive_types)

        if gen_key:
            deidentify.save_key_to_file()
        deidentify.read_key_from_file()

        for prefix in self._bucket_list_folders():
            list_obj_files = self.s3_client.list_objects_v2(Bucket=self.bucket_source, 
                                                            Prefix=prefix)
            for f in list_obj_files.get('Contents'):
                file_path = f.get('Key')
                obj_file = self.s3_client.get_object(Bucket=self.bucket_source, 
                                                Key=file_path)
                text_source = obj_file['Body'].read().decode('utf-8')

                if 0 == len(text_source):
                    continue
                # print('\ntext_source:\n{}\n'.format(text_source))

                dict_pii_report = comprehend.detect_pii_entities(text_source)
                # print('\ndict_pii_report:\n{}\n'.format(dict_pii_report))

                deidentify_text = deidentify.deidentify(raw_text=text_source, 
                                                        dict_sensitive=dict_pii_report, 
                                                        encryption_type=encryption_type)
                # print('\deidentify_text:\n{}\n'.format(deidentify_text))

                # Convert the string content to bytes
                binary_json_content = json.dumps(deidentify_text).encode()   
                # rename the file to have '_deidentified.txt' ending
                file_path_deidentified = file_path.replace('.txt', '_deidentified.txt') 
                # save the deidentified file in s3  
                self.s3_client.put_object(Body=binary_json_content, Bucket=self.bucket_deidentified, Key=file_path_deidentified)
                print('\nfile: {}'.format(file_path))
