from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

mport os
from base64 import urlsafe_b64encode, urlsafe_b64decode

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
    )

    return public_key_pem.decode('utf-8'), private_key_pem.decode('utf-8')