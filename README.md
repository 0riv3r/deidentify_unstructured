# deidentify unstructured
de-identifying of unstructured data and re-identifying of structured data using deterministic aead encryption

# packages:
        ~ conda install -c conda-forge awscli boto3 aws-sam-cli aws-sam-translator
        ~ conda install -c conda-forge pycryptodome

# De-Identified clear-text data

        "email(53)_6kazCzwakI3FW+1UOC+RgdDFiQ==&YDn2d0MIUa9cW5LNfXR0KQ=="  

        "name(41)_vT5/iAaH4IAAxEE=&UTmaUqau3NB3WHyXJPHnAQ=="  

# Re-Identify de-identified data
There is a HMac test to ensure integrity and to prevent chosen-ciphertext-attack    
If the cryptographic signature is broken, we get the following custom exception:   

        Error: MAC verification failed, decryption aborted!

This is also the exception we get if we try to re-identify with the wrong header.  
This what makes the possibility of granular destruction.  

# Granular destruction
Each granularity gets its own header-text and a generated header-crypto-token (128 bit)   
In de-identification the cryptography signature includes the header-token.    
In re-identification, we must provide the right header-token, 
otherwise the cryptography signature will fail and decryption will not be possible.  

The headers are saved in the headers.json file.  
Manage the headers using the headers.py module.  

# Cryptography & ciphers
## Deterministic AEAD
Deterministic Authenticated Encryption with Associated Data   
Provide security against chosen ciphertext attack   

## encryption key
Crypto.Random    
Symmetric, 256 bits (32 bytes)     
provide security against chosen-ciphertext attack   

## Block cipher
AES-128 (block size) Mode-SIV (Synthetic IV- AEAD)    
nonce misuse-resistant     
Operating without a nonce is not an error. the cipher simply becomes deterministic.    

## Stream cipher
ChaCha20-Poly1305   
ChaCha20: Stream cipher    
Poly1305: HMAC (256 bit)    
Quantum resistant   
Like the cipher used in:   
- CyberArk’s Searchable Encryption   
- HashiCorp (according to their blog)   

TLS use ChaCha20 without Poly1305   

    
