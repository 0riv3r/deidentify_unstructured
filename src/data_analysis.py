'''
unstructured/data_analysis.py

This is only for the demo!

performs some faked data analysis
'''
import json
import re
from datetime import date

class Analysis:

    def __init__(self, s3_client, 
                 bucket_deidentified, 
                 bucket_results,
                 list_sensitive_types) -> None:
        self.s3_client = s3_client
        self.bucket_deidentified = bucket_deidentified
        self.bucket_results = bucket_results
        self.list_sensitive_types = list_sensitive_types

    def _bucket_list_folders(self):
        list_objects = self.s3_client.list_objects_v2(Bucket=self.bucket_deidentified, 
                                                      Prefix='', 
                                                      Delimiter='/')
        for content in list_objects.get('CommonPrefixes', []):
            yield content.get('Prefix')

    def _get_deidentified_items(self, deidentified_text):
        deidentified_items = []
        try:

            for type_item in self.list_sensitive_types:
                '''
                Use the syntax "%s" % var within a regular expression to place the value of var in the location of the string "%s".
                email(53)_BPI6eaqrUuLkIwCJkYpMo+mcMA==&jEMq6TnNXk/K/svvlgAa1A==
                name(45)_dfRGMkq6s+4H3XQsKg==&V/mK24IBu2COFr5rHOBfPA==
                '''
                tuple_indices=[(match_item.start(1),match_item.end(1)) for match_item in re.finditer("%s\(([0-9]+)\)_" % type_item,deidentified_text)]
                
                for indices_item in tuple_indices:
                    number_of_chars = deidentified_text[int(indices_item[0]):int(indices_item[1])]
                    start = int(indices_item[1]) - (len(type_item) + 3)
                    end = int(indices_item[1])+ 2 + int(number_of_chars)
                    deidentified_items.append(deidentified_text[start:end])              

        except AttributeError:
            # not found
            print('Deidentified items not found')
        return deidentified_items

    def _get_timestamp_items(self, deidentified_text):
        str_regex = "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}\+[0-9]{2}:[0-9]{2}"
        try:
            timestamp_items = set(re.findall(str_regex, deidentified_text))
        except AttributeError:
            # not found
            print('Timestamp instances not found')

        # convert the set timestamp_items to list and return it
        return [*timestamp_items, ]

    def compute_data_analysis(self, header_name):
        '''
        1. create a list of all the first level folders in the source bucket
        2. read each file in the bucket
        3. perfrom the some fake data analysis (for the demo)
        4. save the analysis results in a dedicated s3 bucket
        '''
        analysis_results_content = {}
        for prefix in self._bucket_list_folders():
            list_obj_files = self.s3_client.list_objects(Bucket=self.bucket_deidentified, 
                                                         Prefix=prefix)
            for f in list_obj_files.get('Contents'):
                file_path = f.get('Key')
                # analyze only the files with the given header
                if header_name not in file_path:
                    continue

                obj_file = self.s3_client.get_object(Bucket=self.bucket_deidentified, 
                                                     Key=file_path)
                text_content = obj_file['Body'].read().decode('utf-8')

                deidentified_items = self._get_deidentified_items(text_content)
                timestamp_items = self._get_timestamp_items(text_content)

                for idx, item in enumerate(deidentified_items):
                    if idx < len(timestamp_items):
                        analysis_results_content.update({item: timestamp_items[idx]})
                    else:
                        analysis_results_content.update({item: timestamp_items[idx % len(timestamp_items)]})

        # Convert the string content to bytes
        binary_analysis_results_content = json.dumps(analysis_results_content).encode()   
        # analysis results file name   
        self.results_file_name = header_name + '_analysis_results_' + str(date.today()) + '.json'
        # save the deidentified file in results s3 bucket   
        self.s3_client.put_object(Body=binary_analysis_results_content, Bucket=self.bucket_results, Key=self.results_file_name)