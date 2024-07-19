from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import os
from base64 import urlsafe_b64encode, urlsafe_b64decode

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_pem.decode('utf-8'), private_key_pem.decode('utf-8')

def encrypt_message(public_key_pem, message):
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    session_key = os.urandom(32)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
   
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Return the encrypted session key, encrypted message, and the tag, all base64 encoded
    return (
        urlsafe_b64encode(encrypted_session_key).decode('utf-8'),
        urlsafe_b64encode(encrypted_message).decode('utf-8'),
        urlsafe_b64encode(encryptor.tag).decode('utf-8'),
        urlsafe_b64encode(nonce).decode('utf-8')
    )




    return public_key_pem.decode('utf-8'), private_key_pem.decode('utf-8')