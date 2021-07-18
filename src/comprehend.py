'''
unstructured/comprehend.py
any questions on this code can be directed to: ofer.rivlin@cyberark.com

a comprehend wrapper to be used in the de-identify/re-identify solution

Please note that used here the CLI API because I did not find the Python API when I wrote this.
Alex showed me later where the boto3 API are:
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/comprehend.html#Comprehend.Client.detect_pii_entities
'''

import subprocess
import json


class Comprehend:

    def __init__(self, list_sensitive_types) -> None:
        '''
        list_sensitive_types: the Comprehend types that we want to find in the data
        '''
        # dict --> {data-type: [list of this data-type findings in the text]}
        self._comprehend_report = {} 
        for pii_type in list_sensitive_types:
            self._comprehend_report.update({pii_type: []})

    @property
    def comprehend_report(self):
        '''
        dict --> {data-type: [list of this data-type findings in the text]}
        '''
        return self._comprehend_report

    def detect_pii_entities(self, raw_data):
        '''
        raw_data: the unstructured text we want to search
        returns:
        dict --> {data-type: [list of this data-type findings in the text]}
        '''

        '''
        Please note that used here the CLI API because I did not find the Python API when I wrote this.
        Alex showed me later where the boto3 API are:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/comprehend.html#Comprehend.Client.detect_pii_entities
        '''
        cmd = ['aws', 'comprehend', 'detect-pii-entities', '--language-code', 'en', '--text', raw_data]

        cmd_output = subprocess.Popen(cmd, stdout = subprocess.PIPE)
        
        # get the output as a string: cmd_output.communicate()
        raw_comprehend_report = json.loads(cmd_output.communicate()[0])
        # print(raw_comprehend_report)

        # filter the findings for what we want
        for entity in raw_comprehend_report["Entities"]:
            if entity['Type'] != 'DATE_TIME': # we don't care about DATE_TIME type
                data = raw_data[int(entity['BeginOffset']) : int(entity['EndOffset'])]
                if entity['Type'] == 'EMAIL':
                    self._comprehend_report["email"].append(data)
                elif entity['Type'] == 'NAME':
                    self._comprehend_report["name"].append(data)
                
        return self._comprehend_report




