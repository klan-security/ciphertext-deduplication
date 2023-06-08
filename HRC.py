import random

'''系统初始化阶段生成素数'''
#素数判定
def Miller_Rabin(n):
    t = n - 1
    s = 0
    #分解n-1=(2^s)*t
    while t & 0x1 == 0:
        t = t >> 1
        s += 1
    for i in range(7):
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
def get_prime(size = 160):
    ret = random.randint(1 << (size - 1) , 1 << size)
    ret |= 1
    while True:
        if Miller_Rabin(ret):
            break
        ret += 2
    return ret

'''中间值、注册阶段的口令传递值与验证值需要快速幂'''
#快速幂
def fast_power(base , power , n):
    ret = 1
    tmp = base
    while power:
        if power & 0x1:
            ret = ret * tmp % n#指数为奇数时，需要提一个底数出来
        tmp = tmp * tmp % n#底数的平方模n
        power >>= 1
    return ret

'''口令传递保护值与传递阶段的口令传递值需要模逆的计算'''
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
    while True:
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
        R = random.randint(1, prime - 1)
        if R != v and R != s:
            break
    U = fast_power(v, R, prime) * (pwd % prime)
    B = fast_power(U, s, prime)
    inv_h = inv(h, prime)
    D = fast_power(inv_h, R, prime) * (B % prime)
    msg = (r * D) % prime
    return msg

#主函数
def main():
    print("注册阶段")
    pwd_in = input("请输入pwd：")
    msg_in = input("请输入msg：")
    pwd = int(pwd_in)
    msg = int(msg_in)
    register_ret = register(pwd, msg)
    v = register_ret[0]
    h = register_ret[1]
    r = register_ret[2]
    s = register_ret[3]
    prime = register_ret[4]
    print("传递阶段")
    msg = transmit(v, h, r, s, pwd, prime)
    print("传递后的值为：", msg)

if __name__ == "__main__":
    main()