from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

class RC4:
    def __init__(self, key):
        self.state = list(range(256))  # Initialize state array
        j = 0
        # Key-scheduling algorithm (KSA)
        for i in range(256):
            j = (j + self.state[i] + key[i % len(key)]) % 256
            self.state[i], self.state[j] = self.state[j], self.state[i]
        self.i = self.j = 0

    def encrypt(self, plaintext):
        return bytes([b ^ self._key_stream_value() for b in plaintext])

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)  # For RC4, encryption and decryption are the same

    def _key_stream_value(self):
        # Pseudo-random generation algorithm (PRGA)
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.state[self.i]) % 256
        self.state[self.i], self.state[self.j] = self.state[self.j], self.state[self.i]
        return self.state[(self.state[self.i] + self.state[self.j]) % 256]

def rsa_decrypt_with_predefined_key(encrypted_message, predefined_private_key_pem):
    predefined_private_key = serialization.load_pem_private_key(
        predefined_private_key_pem,
        password=None, 
        backend=default_backend()
    )
    
    original_message = predefined_private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return original_message

def rsa_encrypt(public_key_pem, message):
    public_key = public_key_pem
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def rsa_decrypt(private_key_pem, encrypted_message):
    private_key = private_key_pem
    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message

def parse_pkcs1_public_key(pkcs1_public_key_bytes):
    public_key = serialization.load_der_public_key(
        pkcs1_public_key_bytes,
        backend=default_backend()
    )
    return public_key

def parse_pkcs1_private_key(pkcs1_private_key_bytes):
    private_key = serialization.load_der_private_key(
        pkcs1_private_key_bytes,
        password=None,
        backend=default_backend()
    )
    return private_key

rc4_key = os.urandom(32)

print("RC4 KEY : ")
print(rc4_key)

public_key = parse_pkcs1_public_key(bytes(public_key_der))

ret = rsa_encrypt(public_key, rc4_key)

print("Encrypted RC4 KEY : ")
print(ret)

private_key = parse_pkcs1_private_key(bytes(private_key_der))
decrypt_ret = rsa_decrypt(private_key, ret)
print("Decrypted RC4 KEY : ")
print(decrypt_ret)
