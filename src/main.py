'''
unstructured/main.py
'''

import boto3

from unstructured import Unstructured
from data_analysis import Analysis

from structured import Structured
from encryption_types import EncryptionType

s3_client = boto3.client('s3')
bucket_source ='deidentify-unstructured-source'
bucket_deidentified = 'deidentify-unstructured-de-identified'
bucket_analyzed = 'deidentify-unstructured-analyzed'
bucket_reidentified = 'deidentify-unstructured-re-identified'
list_sensitive_types = ["email", "name"]

obj_unstructured = Unstructured(s3_client=s3_client,
                            bucket_source=bucket_source,
                            bucket_deidentified=bucket_deidentified,
                            list_sensitive_types=list_sensitive_types,
                            bucket_analyzed=bucket_analyzed,
                            bucket_reidentified=bucket_reidentified)

obj_unstructured.deidentify(encryption_type=EncryptionType.STREAM,
                            gen_key=True)

obj_analysis = Analysis(s3_client=s3_client, 
                        bucket_deidentified=bucket_deidentified,
                        bucket_results=bucket_analyzed,
                        list_sensitive_types=list_sensitive_types)

obj_analysis.compute_data_analysis()


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

obj_structured.reidentify(encryption_type=EncryptionType.STREAM)