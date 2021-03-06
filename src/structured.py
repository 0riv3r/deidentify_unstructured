'''
structured.py

manage the de-identify and re-identify of structured data.
We know where the PII data is, no use of AWS Comprehend is required with structured data.

The assumption for this specific POC is that the original data is unstructured, but that the 
analysis results are structured.
therefore we don't have in th POC de-identifying of structured data, 
so the de-identify methods in this 'structured.py' file are not as complete as with the ones
in the 'unstructured.py' file.
If this is required I have this code elsewhere.

If you need help with this please contact me: ofer.rivlin@cyberark.com
'''

import json
from datetime import date

from de_identify import Deidentify
from structured_re_identify import Reidentify

from decryption_exception import DecryptionException


class Structured:

    def __init__(self, 
                 s3_client, 
                 bucket_source, 
                 bucket_deidentified, 
                 list_sensitive_fields,
                 bucket_analyzed,
                 bucket_reidentified) -> None:
        '''
        :param str bucket_source: the source data s3 bucket
        :param str bucket_deidentified: the s3 bucket where the de-identified data should be stored 
        :param list list_sensitive_fields: the json fields where the pii data is (e.g. 'identityId')
        :param str bucket_analyzed: the s3 bucket where the DE-identified analysis results data should be stored
        :param str bucket_reidentified: the s3 bucket where the RE-identified analysis results data should be stored
        '''
        self.s3_client = s3_client
        self.bucket_source = bucket_source
        self.bucket_deidentified = bucket_deidentified
        self.list_sensitive_fields = list_sensitive_fields
        self.bucket_analyzed = bucket_analyzed
        self.bucket_reidentified = bucket_reidentified
        self.max_manipulated_files = 1 # to limit the number of manipulated files in the poc/demo (one file per folder)
        
    def _bucket_list_folders(self):
        '''
        return list of the folders in the bucket
        '''
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
        if gen_key:
            # generate a new cryptography key - this overwrites the previous key!
            deidentify.save_key_to_file()
        deidentify.read_key_from_file()

        i=0 # use in limiting the number of manipulated files in the poc
        for prefix in self._bucket_list_folders():
            # get the files under each folder
            list_obj_files = self.s3_client.list_objects(Bucket=self.bucket_source, 
                                                         Prefix=prefix)
            for f in list_obj_files.get('Contents'):
                file_path = f.get('Key')
                obj_file = self.s3_client.get_object(Bucket=self.bucket_source, 
                                                Key=file_path)
                # the file content in text
                json_content = json.loads(obj_file['Body'].read().decode('utf-8'))

                # create dict_sensitive:
                # {field1: ['data1', 'data2'], field2: ['data1', 'data2']}
                dict_sensitive = {}

                for field in self.list_sensitive_fields:                # loop through the sensitive fields
                    fields_unique_sensitive_values = set()              # unique sensitive values in a file
                    for row in json_content:                            # row is a transaction in the file 
                        fields_unique_sensitive_values.add(row[field])  # add each unique sensitive value of that field
                    dict_sensitive.update({field: list(fields_unique_sensitive_values)})

                # deidentify the sensitive data
                json_deidentify_text = deidentify.deidentify(json_raw_text=json_content,
                                                             dict_sensitive=dict_sensitive,
                                                             encryption_type=encryption_type)

                # Convert the string content to bytes
                binary_json_content = json.dumps(json_deidentify_text).encode()   
                # save the deidentified file in s3         
                self.s3_client.put_object(Body=binary_json_content, Bucket=self.bucket_deidentified, Key=file_path)
                print('\nfile: {}'.format(file_path))

                i += 1
                if self.max_manipulated_files < i:
                    break

    
    def reidentify(self, encryption_type, header_token, header_name):
        '''
        :param EncryptionType enum encryption_type: EncryptionType.BLOCK / EncryptionType.STREAM
        :param str header_token: the header string token (base64)
        '''

        '''
        1. create a list of all the first level folders in the analyzed data bucket
        2. read each file in the bucket
        3. reidentify each file
        4. save every reidentified file with the same path and name in the deidentified bucket
        '''
        reidentify = Reidentify()
        reidentify.read_key_from_file()

        for file in self.s3_client.list_objects(Bucket=self.bucket_analyzed)['Contents']:
            analysis_results_file_key = file['Key']  # get the file name
            # re-identify only the files with the given header
            if header_name not in analysis_results_file_key:
                continue

            obj_file = self.s3_client.get_object(Bucket=self.bucket_analyzed, 
                                                Key=analysis_results_file_key)
            json_content_analysis_results = json.loads(obj_file['Body'].read().decode('utf-8'))
            # print(json_content_analysis_results)

            try:
                json_reidentified_content = reidentify.reidentify(json_deidentified=json_content_analysis_results, 
                                                                list_deidentified_fields=self.list_sensitive_fields,
                                                                encryption_type=encryption_type,
                                                                header_token=header_token)

                # Convert the string content to bytes
                binary_reidentified_content = json.dumps(json_reidentified_content).encode()   
                # re-identified results file name     
                reidentified_results_file_name = 'reidentified_' + analysis_results_file_key + '.json'
                # save the deidentified file in results s3 bucket   
                self.s3_client.put_object(Body=binary_reidentified_content, 
                                        Bucket=self.bucket_reidentified, 
                                        Key=reidentified_results_file_name)

            except DecryptionException as e:
                # print('\n{}\n'.format(e))
                print('\nFail to re-identify data of header: {}\n'.format(header_name))



