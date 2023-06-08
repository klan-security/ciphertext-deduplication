#密文去重
'''
以文件的明文哈希作为文件标识，判断文件是否是初次上传
初次上传时，客户端与服务器运行HCR的注册阶段，安全地将加密密钥存储在云端
非初次上传时，客户端与服务器运行HCR的传递阶段，从服务器那里得到加密密钥
密钥的计算需要明文信息，因此不需要身份验证。即敌手无法与服务器交互得到加密密钥
'''

import pymysql
import os
from Cryptodome.Cipher import AES
from Cryptodome import Random
import random
import binascii
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
import pickle
from gooey import Gooey, GooeyParser
import argparse
import time
#文件的MD5哈希，作为文件标识
'''
input：filepath，文件地址
output：hexdigest，文件摘要
'''
import hashlib
def get_file_md5(filepath):
    m = hashlib.md5()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            m.update(data)
    return m.hexdigest()
def get_str_md5(content):
    m = hashlib.md5(content)
    return m.hexdigest()

#数据库交互
'''
文件上传时，需要判断此文件的摘要是否已经存在。因而考虑将文件的摘要存入数据库中。
客户端与服务器交互运行HCR时，也需要在服务器端存储一些数据。
'''
class DoMysql:
    #初始化
    def __init__(self):
        #创建连接
        self.conn = pymysql.Connect(
          host = 'localhost',
          port = 3306,
          user = 'root',
          password = 'root',
          db = 'test',
          charset = 'utf8',
          cursorclass = pymysql.cursors.DictCursor  #以字典的形式返回数据
        )
        #获取游标
        self.cursor = self.conn.cursor()
    #返回多条数据
    def fetchAll(self, sql, params):
        self.cursor.execute(sql, params)
        return self.cursor.fetchall()
    #插入、查询数据
    def insert_select(self, sql, params):
        result = self.cursor.execute(sql, params)
        self.conn.commit()
        return result
    #更新数据
    def update(self, sql, params):
        result = self.cursor.execute(sql, params)
        self.conn.commit()
        return result
    #关闭连接
    def close(self):
        self.cursor.close()
        self.conn.close()

#文件加密
'''
出于隐私性的考虑，用户将文件加密后上传到云端。
EC算法在文件的熵值较小时，易受离线穷举攻击。
产生随机密钥，使用AES算法对文件进行加密。
'''
class Aescrypt():
    #初始化，设定密钥与初始向量。此处采用CBC模式
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
        with open(filepath, 'rb') as f:
            data = f.read()
        data = self.aesencrypt(data)
        if not encrypt_filepath:
            filepath = os.path.split(filepath)
            encrypt_filepath = filepath[0] + '/encrypt_' + filepath[1]
        with open(encrypt_filepath, 'wb') as f:
            f.write(data)
        return encrypt_filepath
    def decrypt_file(self, encrypt_filepath, decrypt_filepath=''):
        with open(encrypt_filepath, 'rb') as f:
            data = f.read()
        data = self.aesdecrypt(data)
        if not decrypt_filepath:
            encrypt_filepath = os.path.split(encrypt_filepath)
            decrypt_filepath = encrypt_filepath[0] + '/decrypt_' + encrypt_filepath[1]
        with open(decrypt_filepath, 'wb') as f:
            f.write(data)
        return decrypt_filepath

#密钥传递
'''
为了实现解密，需要将首位用户的加密密钥安全地存储在云端。
即只有拥有文件的用户才可以在与服务器的交互中恢复出密钥。
'''
#素数判定
def Miller_Rabin(n):
    t = n - 1
    s = 0
    while t & 0x1 == 0:
        t = t >> 1
        s += 1
    for i in range(10):
        b = random.randint(2 , n - 2)
        r = fast_power(b , t , n)
        if r == 1 or r == n - 1:
            continue
        for j in range(s - 1):
            r = fast_power(r , 2 , n)
            if r == n - 1:
                break
        else:
            return False
    return True
#生成素数
def get_prime(size = 50):
    ret = random.randint(1 << (size - 1) , 1 << size)
    ret |= 1
    while True:
        if Miller_Rabin(ret):
            break
        ret += 2
    return ret
#模快速幂
def fast_power(base , power , n):
    ret = 1
    tmp = base
    while power:
        if power & 0x1:
            ret = ret * tmp % n#指数为奇数时，需要提一个底数出来
        tmp = tmp * tmp % n#底数的平方模n
        power >>= 1
    return ret
#求最大公因数
def gcd(a , b):
    if a < b:
        a , b = b , a
    while b != 0:
        a ,  b = b ,a % b
    return a
#求解逆元
def inv(a , b):
    if gcd(a , b) != 1:
        print("a和b不互素，不存在逆元")
        return None
    s1 , s2 , r1 = 1 , 0 , a
    t1 , t2 , r2 = 0 , 1 , b
    while r2 != 1:
        q = r1 // r2
        temp1 , temp2 , temp3 = s1 , t1 , r1
        s1 , s2 , r1 = s2 , (temp1 - q * s2) , r2
        t1 , t2 , r2 = t2 , (temp2 - q * t2) , (temp3 - q * r2)
    return s2
#注册阶段
def register(pwd, msg):
    prime = get_prime()
    v = random.randint(1, prime - 1)
    s = random.randint(1, prime - 1)
    h = fast_power(v, s, prime)
    D = fast_power(pwd, s, prime)
    inv_D = inv(D, prime)
    r = (msg * inv_D) % prime
    return (v, h, r, s, prime)
#传递阶段
def transmit(v, h, r, s, pwd, prime):
    while True:
        R = random.randint(2, prime - 1)
        if R != v and R != s:
            break
    U = fast_power(v, R, prime) * (pwd % prime)
    B = fast_power(U, s, prime)
    inv_h = inv(h, prime)
    D = fast_power(inv_h, R, prime) * (B % prime)
    msg = (r * D) % prime
    return msg

#文件逆序
'''
HCR中，由文件所有者共享的秘密信息定义为文件哈希与逆序后哈希的异或
'''
def File_Reverse(in_filepath, out_filepath = ''):
    with open(in_filepath, 'rb') as f:
        tmp = f.read()
    if not out_filepath:
        in_filepath = os.path.split(in_filepath)
        out_filepath = in_filepath[0] + '/rev_' + in_filepath[1]
    with open(out_filepath, 'wb') as f:
        f.write(tmp[::-1])
    return out_filepath
def str2int(message):
    str_bytes = bytes(message , encoding='utf-8')
    ret = int(binascii.hexlify(str_bytes) , 16)
    return ret
def int2str(message):
    ret = binascii.unhexlify(hex(message)[2:])
    return ret
def get_pwd(filepath):
    Hexdigester = get_file_md5(filepath)
    rev_filepath = File_Reverse(filepath)
    Hexdigester_inv = get_file_md5(rev_filepath)
    return str2int(Hexdigester) ^ str2int(Hexdigester_inv)
  
#产生随机字符串
'''
用户登录时的口令验证采用挑战-响应机制
'''
def get_random_str():
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz,.'
    length = len(base_str) - 1
    for i in range(16):
        random_str += base_str[random.randint(0, length)]
    return random_str

def user_login():
    user_name = var_user_name.get()
    user_pwd = var_user_pwd.get()
    pwd = user_pwd.encode()
    user_pwd_hash = get_str_md5(pwd)
    mysql = DoMysql()
    sql = 'select * from user where username = %s'
    result = mysql.insert_select(sql, user_name)
    if not result:
        is_sign_up = tk.messagebox.askyesno('您尚未注册，是否现在注册？')
        if is_sign_up:
            user_sign_up()
    else:
        tmp = mysql.fetchAll(sql, user_name)
        pwd_hash = tmp[0].get('hash')
        random_str = get_random_str()
        iv = Random.new().read(AES.block_size)
        aescryptor1 = Aescrypt(user_pwd_hash, iv)
        ret1 = aescryptor1.aesencrypt(random_str)
        aescryptor2 = Aescrypt(pwd_hash, iv)
        ret2 = aescryptor2.aesencrypt(random_str)
        if ret1 == ret2:
            window.destroy()
            start()
        else:
            tk.messagebox.showerror(message = "口令错误")

def user_sign_up():
    def signyes():
        username = sign_up_name.get()
        password = sign_up_pwd.get()
        conf = sign_up_conf.get()
        pwd = password.encode()
        password_hash = get_str_md5(pwd)
        if username == '' or password == '':
            tk.messagebox.showerror(message = "用户名、口令不能为空")
        elif password != conf:
            tk.messagebox.showerror(message = "前后两次口令不一致")
        else:
            mysql = DoMysql()
            sql = 'select * from user where username = %s'
            result = mysql.insert_select(sql, username)
            if result:
                tk.messagebox.showerror(message = "用户已存在")
            else:
                sql = 'insert into `user`(`username`,`hash`) values(%s, %s)'
                params = (username, password_hash)
                mysql.insert_select(sql, params)
                tk.messagebox.showinfo(message = '注册成功')
                window_sign.destroy()

    window_sign = tk.Toplevel(window)
    window_sign.geometry('450x300')
    window_sign.title('注册界面')

    tk.Label(window_sign, text = '用户名：').place(x = 50, y = 130)
    tk.Label(window_sign, text = '口令：').place(x = 50, y = 160)
    tk.Label(window_sign, text = "确认口令：").place(x = 50, y = 190)

    sign_up_name = tk.StringVar()
    sign_up_pwd = tk.StringVar()
    sign_up_conf = tk.StringVar()

    entry_sign_up_name = tk.Entry(window_sign, textvariable = sign_up_name)
    entry_sign_up_name.place(x = 160, y =130)
    entry_sign_up_pwd = tk.Entry(window_sign, textvariable = sign_up_pwd, show = '*')
    entry_sign_up_pwd.place(x = 160, y =160)
    entry_sign_up_conf = tk.Entry(window_sign, textvariable = sign_up_conf, show = '*')
    entry_sign_up_conf.place(x = 160, y =190)
    btn_conf = tk.Button(window_sign, text = '确定', command = signyes)
    btn_conf.place(x = 180, y = 230)

def start():
    def uploadyes():
        upload_filepath = filedialog.askopenfilename()
        entry1.insert(0, upload_filepath)
        HexDigest = get_file_md5(upload_filepath)
        mysql = DoMysql()
        sql = 'select * from file where hash = %s'
        result = mysql.insert_select(sql, HexDigest)
        if result:
            start = time.process_time()
            print("文件摘要为：", HexDigest)
            tk.messagebox.showinfo(message = "数据库中检索到文件摘要" + HexDigest + ",文件已存储在云端")
            tmp = mysql.fetchAll(sql, HexDigest)
            mysql.close()
            v = tmp[0].get('v')
            h = tmp[0].get('h')
            r = tmp[0].get('r')
            S = tmp[0].get('S')
            prime = tmp[0].get('prime')
            pwd = get_pwd(upload_filepath)
            key = transmit(v, h, r, S, pwd, prime)
            tk.messagebox.showinfo(message = "由HCR传递阶段得到文件初次上传者的文件存储密钥为：" + str(key))
            end = time.process_time()
            tk.messagebox.showinfo(message = "本次程序运行时间为：" + str(end - start) + "\n")
        else:
            start = time.process_time()
            tk.messagebox.showinfo(message = "数据库中未检索到文件摘要" + HexDigest + ",为文件的初次上传")
            key_in = get_prime(16)
            tk.messagebox.showinfo(message = "随机产生文件存储密钥" + str(key_in))
            key = int2str(key_in)
            iv = Random.new().read(AES.block_size)
            aescryptor = Aescrypt(key, iv)
            store_filepath = aescryptor.encrypt_file(upload_filepath)
            pwd = get_pwd(upload_filepath)
            register_ret = register(pwd, key_in)
            sql = 'insert into `file`(`hash`,`v`, `h`, `r`, `S`, `prime`, `filepath`, `iv`) values(%s, %s, %s, %s, %s, %s, %s, %s)'
            params = (HexDigest, register_ret[0], register_ret[1], register_ret[2], register_ret[3], register_ret[4], store_filepath, iv)
            mysql.insert_select(sql, params)
            mysql.close()
            end = time.process_time()
            tk.messagebox.showinfo(message = "本次程序运行时间为：" + str(end - start) + "\n")

    def downyes():
        HexDigest = file_pointer.get()
        key_in = file_key.get()
        key = int2str(key_in)
        mysql = DoMysql()
        sql = 'select * from file where hash = %s'
        result = mysql.fetchAll(sql, HexDigest)
        filepath = result[0].get('filepath')
        iv = result[0].get('iv')
        aesdecryptor = Aescrypt(key, iv)
        store_filepath = aesdecryptor.decrypt_file(filepath)
        tk.messagebox.showinfo(message = "解密后的文件存储在" + store_filepath)
        HexDigest_new = get_file_md5('D:\decrypt_encrypt_test.pptx')
        print(HexDigest_new)
        if HexDigest == HexDigest_new:
            tk.messagebox.showinfo("下载文件的标签与存储的文件标签一致，文件下载成功")
        else:
            tk.messagebox.showerror("下载文件的标签与存储的文件标签不一致，文件下载失败")
    
    window_file = tk.Tk()
    window_file.geometry('450x300')
    window_file.title("文件管理界面")

    btnup = tk.Button(window_file, text = "上传文件", command = uploadyes)
    btnup.place(x = 50, y = 50)
    entry1 = tk.Entry(window_file, width = '40')
    entry1.place(x = 120, y = 55)

    tk.Label(window_file, text = '文件指针：').place(x = 50, y = 130)
    tk.Label(window_file, text = '文件存储密钥：').place(x = 50, y = 160)

    file_pointer = tk.StringVar()
    file_key = tk.IntVar()

    entry_file_pointer = tk.Entry(window_file, textvariable = file_pointer)
    entry_file_pointer.place(x = 160, y =130)
    entry_file_key = tk.Entry(window_file, textvariable = file_key, show = '*')
    entry_file_key.place(x = 160, y =160)
    btn_down = tk.Button(window_file, text = '下载', command = downyes)
    btn_down.place(x = 140, y = 230)

window = tk.Tk()
window.title("登录界面")
window.geometry('450x300')

tk.Label(window, text = '用户名：').place(x = 50, y = 150)
tk.Label(window, text = '口令：').place(x = 50, y = 190)

var_user_name = tk.StringVar()
entry_user_name = tk.Entry(window, textvariable = var_user_name)
entry_user_name.place(x = 160, y = 150)
var_user_pwd = tk.StringVar()
entry_user_pwd = tk.Entry(window, textvariable = var_user_pwd, show = '*')
entry_user_pwd.place(x = 160, y = 190)
btn_login = tk.Button(window, text = "登录", command = user_login)
btn_login.place(x = 170, y = 230)
btn_sign_up = tk.Button(window, text = "注册", command = user_sign_up)
btn_sign_up.place(x = 270, y = 230)

if __name__ == "__main__":
    window.mainloop()