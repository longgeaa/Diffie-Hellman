#coding:utf-8
#from netfilterqueue import NetfilterQueue
#import nfqueue
from pypacker import interceptor
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from scapy.all import *
import os
import socket  # 导入 socket 模块
import random
from Crypto.Cipher import AES
import hashlib
from binascii import b2a_hex, a2b_hex

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

# 如果text不足16位的倍数就用空格补足为16位
def add_to_16(text):
    if len(text.encode('utf-8')) % 16!=0:
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
    print(text)
    print(a2b_hex(text))
    plain_text = cryptos.decrypt(a2b_hex(text))
    return bytes.decode(plain_text).rstrip('\0')






global server_time,client_time,Km1,Km2,Bm,Bc,am,pm
server_time=0
client_time=0
os.system('sudo iptables -F')
os.system("sudo iptables -I INPUT 1 -p tcp --dport 12346 -j NFQUEUE --queue-balance 0:2")
os.system("sudo iptables -I INPUT 1 -p tcp --sport 12346 -j NFQUEUE --queue-balance 0:2")

def print_and_accept(ll_data, ll_proto_id, data, ctx):
    global server_time,client_time,Km1,Km2,Bm,Bc,am,pm
    scapy_pkt = ip.IP(data)
    tcp_pkt = scapy_pkt[tcp.TCP]
    print(tcp_pkt.body_bytes)
    print('###########################################\n',scapy_pkt)
    print('@@@@@@@@@',type(tcp_pkt.sport))
    if tcp_pkt.body_bytes==b'':
        print('1111111111111111111111111111111111111111')
        return data, interceptor.NF_ACCEPT
    elif tcp_pkt.sport==12346:    
        if server_time==0:
            gs,ps,As=tcp_pkt.body_bytes.decode('utf-8').split("*")
            gs,ps,As=int(gs),int(ps),int(As)
            pm,gm=get_prime(50)
            am=random.randint(1,pm-1)
            Am=fastPower(gm,am,pm)
            bm=random.randint(1,pm-1)
            Bm=fastPower(gs, bm, ps)
            Km1=fastPower(As, bm, ps)
            print('server time=0....',gs,ps,As,Bm,Km1)
            print(gm,pm,Am)
            g_p_A=str(gm)+"*"+str(pm)+"*"+str(Am)
            scapy_pkt[tcp.TCP].body_bytes=g_p_A.encode('utf-8')
            server_time+=1
        else:
            datas=tcp_pkt.body_bytes
            if type(datas)!=bytes:
                datas=bytes(str(datas),'utf-8')
            print('server time>1..........',Km1,datas)
            datas=decrypt(str(Km1),datas)
            print("server message:",datas)
            datas=encrypt(str(Km2),datas)
            scapy_pkt[tcp.TCP].body_bytes=datas
        print('****************************************',scapy_pkt)
        scapy_pkt[tcp.TCP].sum=0
        return scapy_pkt.bin(), interceptor.NF_ACCEPT
    elif tcp_pkt.dport==12346:
        if client_time==0:
            Bc=tcp_pkt.body_bytes.decode('utf-8')
            Bc=int(Bc)
            print("@@@@@@@@@@@@@@@@@@@@:",Bm,Bc)
            scapy_pkt[tcp.TCP].body_bytes=str(Bm).encode('utf-8')
            #pkt.set_payload(bytes(str(scapy_pkt),'utf-8'))
            Km2=fastPower(Bc,am, pm)
            print('************************************',scapy_pkt)
            client_time+=1
        else:
            datac=tcp_pkt.body_bytes
            if type(datac)!=bytes:
                datac=bytes(str(datac),'utf-8')
            datac=decrypt(str(Km2),datac)
            print("client message:",datac)
            datac=encrypt(str(Km1),datac)
            scapy_pkt[tcp.TCP].body_bytes=datac
        scapy_pkt[tcp.TCP].sum=0
        return scapy_pkt.bin(), interceptor.NF_ACCEPT
    else:
        return data, interceptor.NF_ACCEPT
ictor = interceptor.Interceptor()
ictor.start(print_and_accept, queue_ids=[0, 1, 2])
import time
time.sleep(999)
ictor.stop()