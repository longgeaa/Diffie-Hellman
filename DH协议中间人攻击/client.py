#coding:utf-8
import socket  # 导入 socket 模块
import random
from Crypto.Cipher import AES
import hashlib
import os

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex


# 如果text不足16位的倍数就用空格补足为16位
def add_to_16(text):
    if len(text.encode('utf-8')) % 16:
        add = 16 - (len(text.encode('utf-8')) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text.encode('utf-8')


# 加密函数
def encrypt(K,text):
    key = add_to_16(K)
    mode = AES.MODE_CBC
    iv = b'qqqqqqqqqqqqqqqq'
    text = add_to_16(text)
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return b2a_hex(cipher_text)


# 解密后，去掉补足的空格用strip() 去掉
def decrypt(K,text):
    key = add_to_16(K)
    iv = b'qqqqqqqqqqqqqqqq'
    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)
    plain_text = cryptos.decrypt(a2b_hex(text))
    return bytes.decode(plain_text).rstrip('\0')



def fastPower(x, n, mod):
    t = x
    res = 1
    while n: 
        if n & 1:
            res = ((res % mod) * (t % mod)) % mod
        t = ((t % mod) * (t % mod)) % mod
        n >>= 1
    return res % mod


s = socket.socket()  # 创建 socket 对象
host = socket.gethostname()  # 获取本地主机名
port = 12346  # 设置端口号

s.connect(('127.0.0.1', port))
#s.send(encrypt('init'))
pram = s.recv(1024)

g, p, A = pram.decode('utf-8').split('*')
print(g,p,A)
g, p, A=int(g),int(p),int(A)
b = random.randint(1, p-1)
B = fastPower(g, b, p)
K = fastPower(A, b, p)
s.send(str(B).encode('utf-8'))
while 1:
    data=input("please input your data(q quit):")
    if data=='q':
        item=encrypt(str(K),data)
        s.send(item)
        print("send:",item)
        break
    item=encrypt(str(K),data)
    s.send(item)
    print("send:",item)
    print(decrypt(str(K),s.recv(1000)))

s.close()
os.system("iptables -X")
os.system("iptables -F")
print(K)
'''47.94.252.63'''

