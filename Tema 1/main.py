import secrets

from Crypto.Cipher import AES

f = open("plaintext.txt", "r")
plaintext=f.read().encode()
f.close()
Key='abdgehrjtkditrex'.encode()
iv='nfigekftjsdgneis'.encode()

def xor(a,b):
    return bytes(a ^ b for a, b in zip(a, b))
def keyManager():
    K=secrets.token_hex(16).encode()
    cipher=AES.new(Key,AES.MODE_ECB)
    encryptedKey=cipher.encrypt(K)
    return encryptedKey
K1=keyManager()
def nodeA(enccyptionType):
    cipher = AES.new(Key, AES.MODE_ECB)
    print("nodeA: sending key request")
    key=cipher.decrypt(K1)
    print("nodeA: decrypted key")
    if (enccyptionType=="ECB"):
        text = ECBFileEncryptor(key)
        print("nodeA: sending message to nodeB")
        nodeB(text,"ECB")
    elif(enccyptionType=="OFB"):
        text=OFBFiileEncryptor(key)
        print("nodeA: sending message to nodeB")
        nodeB(text,"OFB")
    else: print("invalid supported encryption")

def nodeB(text,encryptionType):
    cipher = AES.new(Key, AES.MODE_ECB)
    print("nodeB: sending key request")
    key = cipher.decrypt(K1)
    print("nodeB: decrypted key")
    print("nodeB: recieved encrypted text:")
    print(text)
    if(encryptionType=="ECB"):
        print(ECBFileDecryptor(text,key).decode("utf-8"))
    elif (encryptionType == "OFB"):
        print(OFBFileDecryptor(text,key).decode("utf-8"))
    else: print("invalid supported encryption")
def ECBFileEncryptor(K):
    print("Starting ECB file encryption")
    inputText=[plaintext[i:i+16]for i in range(0, len(plaintext), 16)]
    Key=b''+K
    cipher=AES.new(Key,AES.MODE_ECB)
    outputText=b""
    for i in range(0,len(inputText)):
        inputText[i]=cipher.encrypt(inputText[i].ljust(16,b" "))
    for i in range(0,len(inputText)):
        outputText=outputText+inputText[i]
    return  outputText

def ECBFileDecryptor(text,K):
    print("Starting ECB file decryption")
    inputText = [text[i:i + 16] for i in range(0, len(text), 16)]
    cipher = AES.new(K, AES.MODE_ECB)
    outputText = b""
    for i in range(0, len(inputText)):
        inputText[i] = cipher.decrypt(inputText[i].ljust(16, b" "))
    for i in range(0, len(inputText)):
        outputText = outputText + inputText[i]
    return outputText
def OFBFiileEncryptor(K):
    print("Starting OFB file encryption")
    inputText = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]
    Key = b'' + K
    cipher = AES.new(Key, AES.MODE_ECB)
    outputText = b""
    iv2=iv
    for i in range(0, len(inputText)):
        xorKey=cipher.encrypt(iv2)
        iv2=xorKey
        inputText[i] = xor(inputText[i].ljust(16, b" "),xorKey)
    for i in range(0, len(inputText)):
        outputText = outputText + inputText[i]
    return outputText
def OFBFileDecryptor(text,K):
    print("Starting OFB file decryption")
    inputText = [text[i:i + 16] for i in range(0, len(text), 16)]
    Key = b'' + K
    cipher = AES.new(Key, AES.MODE_ECB)
    outputText = b""
    iv2 = iv
    for i in range(0, len(inputText)):
        Key2 = cipher.encrypt(iv2)
        iv2 = Key2
        inputText[i] = xor(inputText[i].ljust(16, b" "), Key2)
    for i in range(0, len(inputText)):
        outputText = outputText + inputText[i]
    return outputText
if __name__ == '__main__':
    choice=input("What encryption do you want?\nECB\nOFB\nExit\n")

    while choice!="Exit":
        if choice=="ECB":
            nodeA("ECB")
        elif choice=="OFB":
            nodeA("OFB")
        else:
            print("invalid choice")
        choice=input()