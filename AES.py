import os
from Cryptodome.Cipher import AES
from Cryptodome import Random

class Aescrypt():
    def __init__(self, key, iv):
        self.key = self.add_16(key)
        self.iv = iv

    def add_16(self, par):
        if type(par) == str:
            par = par.encode()
        while len(par) % 16 != 0:
            par += b'\x00'
        return par

    def aesencrypt(self, text):
        text = self.add_16(text)
        self.aes = AES.new(self.key, AES.MODE_CBC, self.iv) 
        self.encrypt_text = self.aes.encrypt(text)
        return self.encrypt_text

    def aesdecrypt(self, text):
        self.aes = AES.new(self.key, AES.MODE_CBC, self.iv) 
        self.decrypt_text = self.aes.decrypt(text)
        self.decrypt_text = self.decrypt_text.strip(b"\x00")
        return self.decrypt_text
    
    def encrypt_file(self, filepath, encrypt_filepath=''):
        #加载数据
        with open(filepath, 'rb') as f:
            data = f.read()
        #加密数据
        data = self.aesencrypt(data)
        #将加密好的数据写到加密文件上
        if not encrypt_filepath:
            filepath = os.path.split(filepath)
            encrypt_filepath = filepath[0] + '/encrypt_' + filepath[1]
        with open(encrypt_filepath, 'wb') as f:
            f.write(data)

    def decrypt_file(self, encrypt_filepath, decrypt_filepath=''):
        #加载数据
        with open(encrypt_filepath, 'rb') as f:
            data = f.read()
        #加密数据
        data = self.aesdecrypt(data)
        #夹加密好的数据写到加密文件上
        if not decrypt_filepath:
            encrypt_filepath = os.path.split(encrypt_filepath)
            decrypt_filepath = encrypt_filepath[0] + '/decrypt_' + encrypt_filepath[1]
        with open(decrypt_filepath, 'wb') as f:
            f.write(data)
            
if __name__ == '__main__':
    passwd = "123456781234567"
    iv = Random.new().read(AES.block_size)
    aescryptor = Aescrypt(passwd,iv)
    text = b"hello world"
    en_text = aescryptor.aesencrypt(text)
    print("密文:",en_text)
    text = aescryptor.aesdecrypt(en_text)
    print("明文:",text)
    #对文件的加密解密
    aescryptor.encrypt_file('D://hello.pptx')
    aescryptor.decrypt_file('D://encrypt_hello.pptx')