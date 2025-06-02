import oqs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Key Encapsulation using Kyber512
def kyber_key_exchange():
    server = oqs.KeyEncapsulation('Kyber512')
    public_key = server.generate_keypair()
    return server, public_key

def kyber_encapsulate(public_key):
    client = oqs.KeyEncapsulation('Kyber512')
    ciphertext, shared_secret = client.encap_secret(public_key)
    return client, ciphertext, shared_secret

# AES encryption
def encrypt_message(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv + ct_bytes

# AES decryption
def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return pt.decode()

# Dilithium for signing
def generate_dilithium_keys():
    signer = oqs.Signature('Dilithium2')
    public_key = signer.generate_keypair()
    return signer, public_key

def sign_message(signer, message):
    return signer.sign(message)

def verify_signature(public_key, message, signature):
    verifier = oqs.Signature('Dilithium2')
    return verifier.verify(message, signature, public_key)
