import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def keyManager():
    K1=secrets.token_hex(16).encode()