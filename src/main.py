'''
unstructured/main.py
'''

from base64 import b64encode
import boto3

from unstructured import Unstructured
from data_analysis import Analysis

from structured import Structured
from encryption_types import EncryptionType

from headers import Headers

s3_client = boto3.client('s3')
bucket_source ='deidentify-unstructured-source'
bucket_deidentified = 'deidentify-unstructured-de-identified'
bucket_analyzed = 'deidentify-unstructured-analyzed'
bucket_reidentified = 'deidentify-unstructured-re-identified'
list_sensitive_types = ["email", "name"]

# Objects
# -------

obj_header = Headers()

obj_unstructured = Unstructured(s3_client=s3_client,
                                bucket_source=bucket_source,
                                bucket_deidentified=bucket_deidentified,
                                list_sensitive_types=list_sensitive_types,
                                bucket_analyzed=bucket_analyzed,
                                bucket_reidentified=bucket_reidentified)


obj_analysis = Analysis(s3_client=s3_client, 
                        bucket_deidentified=bucket_deidentified,
                        bucket_results=bucket_analyzed,
                        list_sensitive_types=list_sensitive_types)

'''
The assumption here is that our data analysis is in some structured data
therefore we don't have here re-identifying of unstructured data although 
I have implemented this capability in the code
'''
obj_structured = Structured(s3_client=s3_client,
                            bucket_source=bucket_source,
                            bucket_deidentified=bucket_deidentified,
                            list_sensitive_fields=list_sensitive_types,
                            bucket_analyzed=bucket_analyzed,
                            bucket_reidentified=bucket_reidentified)

# functions
# ---------

def set_header(header, header_granular_type="months"):
    obj_header.add_new_header(header_granular_type, header)
    return obj_header.get_header_bytes_token(header_granular_type, header)

def deidentify(header_bytes_token):
    obj_unstructured.deidentify(encryption_type=EncryptionType.BLOCK,
                            gen_key=True,
                            header=header_bytes_token)

def analyze():
    obj_analysis.compute_data_analysis()
    
def reidentify(header_str_token):
    obj_structured.reidentify(encryption_type=EncryptionType.BLOCK, 
                          header_token=header_str_token)

########################
#####   EXECUTE   ######
########################

_header = 'jul21'

header_bytes_token = set_header(header=_header, header_granular_type="months")

deidentify(header_bytes_token)
analyze()

header_str_token = b64encode(header_bytes_token).decode('utf-8')
reidentify(header_str_token)