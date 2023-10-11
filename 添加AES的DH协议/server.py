#coding:utf-8
import socket               # 导入 socket 模块

import random


from threading import Thread

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
global pre_key


def get_key():
    f=open("./password.txt","r")
    for line in f:
        pre_key=line
        break
    f.close()
    return pre_key

def write_password(s):
    f=open("./password.txt","w")
    f.write(s)
    f.close()





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
    print(type(text),type(plain_text))
    return bytes.decode(plain_text).rstrip('\0')





def rabin_miller(num):
    s = num - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1
    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True


def is_prime(num):
    # 排除0,1和负数
    if num < 2:
        return False

    # 创建小素数的列表,可以大幅加快速度
    # 如果是小素数,那么直接返回true
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
    if num in small_primes:
        return True

    # 如果大数是这些小素数的倍数,那么就是合数,返回false
    for prime in small_primes:
        if num % prime == 0:
            return False

    # 如果这样没有分辨出来,就一定是大整数,那么就调用rabin算法
    return rabin_miller(num)

# 得到大整数及其原根
def get_prime(key_size):
    while True:
        num = random.randrange(2**(key_size-1), 2**key_size)
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
        protogen_index=random.randint(0,len(small_primes)-1)
        protogen=small_primes[protogen_index]
        if is_prime(num) and num%protogen!=0:
            return num,protogen
    return

def fastPower(x, n, mod):
    t = x
    res = 1
    while n: 
        if n & 1:
            res = ((res % mod) * (t % mod)) % mod
        t = ((t % mod) * (t % mod)) % mod
        n >>= 1
    return res % mod

def recv_data(c,addr):
    global pre_key
    pre_key=get_key()
    print("new thread")
    p,g=get_prime(50)
    a=random.randint(1,p-1)
    A=fastPower(g,a,p)
    random_string="hello world"
    random_string1=encrypt(str(pre_key),random_string).decode('utf-8')
    g_p_A=str(g)+"*"+str(p)+"*"+str(A)+"*"+random_string1
    g_p_A=encrypt(str(pre_key),g_p_A).decode('utf-8')
    c.send(g_p_A.encode('utf-8'))
    B,ret_random_string=c.recv(1024).decode("utf-8").split("*")
    print(random_string)
    K=fastPower(int(B),a,p)
    print(random_string,ret_random_string)
    if random_string!=ret_random_string:
        print("预共享密钥验证不通过！")
        c.send("wrong pre_key".encode('utf-8'))
        c.close()
        return
    print("预共享密钥验证通过！")
    write_password(str(K))
    c.send("right pre_key".encode('utf-8'))
    while 1:
        data=decrypt(str(K),c.recv(1000))
        print(addr,":",data)
        if data=='q':
            break
        c.send(encrypt(str(K),data))
    #s.send(data)
    c.close()
    return



def server_get_K():
    s = socket.socket()         # 创建 socket 对象
    #host = socket.gethostname() # 获取本地主机名
    port = 12346                # 设置端口
    s.bind(('127.0.0.1', port))        # 绑定端口
    s.listen(5)     # 等待客户端连接
    print("server listening......")

    #print(decrypt(str(c.recv(1024))))
    while True:
            c, addr = s.accept()    #等待客户端连接
            print("{} online".format(addr))
 
            tr = Thread(target=recv_data, args=(c, addr,))   #创建线程为客户端服务
            tr.start()  #开启线程
            tr.join() 
    s.close()

    
    
    


if __name__=="__main__":
    server_get_K()


