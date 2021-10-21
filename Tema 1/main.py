import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def keyManager():
    K=secrets.token_hex(16).encode()
    cipher=AES.new(K,AES.MODE_ECB)
    nonece=cipher.nonce
    encryptedKey=cipher.encrypt(K)
    print("KeyManager:",encryptedKey)
    return encryptedKey,nonece

def nodeA(enccyptionType):
    if (enccyptionType=="ECB"):
        print("ECB")
    elif(enccyptionType=="OFB"):
        print("OFB")
    else: print("invalid supported encryption")
def ECBFileEncriptor(K1):
    print("Starting ECB file encription\n")
    plaintext = open("plaintext.txt", "r")
    inputText=[plaintext[i:i+16]for i in range(0,len(plaintext),16)]
    cipher=AES.new(K1,AES.MODE_ECB)
    nonce=cipher.nonce
    outputText=b""
    for i in range(0,len(inputText)):
        inputText[i]=cipher.encrypt(inputText[i])
    for i in range(0,len(inputText)):
        outputText=outputText+inputText[i]
    print("Encrypted file: ",outputText)

ECBFileEncriptor(secrets.token_hex(16).encode())