import random

def millerrabin_test(p, max_test_times=1000):
    max_test_times = max(1, min(max_test_times, p-2))
    for _ in range(max_test_times):
        x = random.randint(2,p-2)
        if quickpower(x, p-1, p)!=1:
            return False
    return True

def quickpower(b, e, m):
    result = 1
    while e != 0:
        if (e&1) == 1:
            result = (result * b) % m
        e >>= 1
        b = (b*b) % m
    return result

def gcd(a,b):
    return b if a==0 else gcd(b%a, a)

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x
    
def select_pq(l,r):
    a = []
    for i in range(l,r+1):
        if millerrabin_test(i):
            a.append(i)
            if len(a)==2:
                return tuple(a)
    return None

def select_e(fn):
    while True:
        e = random.randint(1, fn-1)
        if extended_gcd(e, fn)[0]==1:
            return e
        
def select_d(e, fn):
    a,b = e,fn
    if a<b:
        a,b = b,a
    _,_,d = extended_gcd(a,b)
    return d % fn
        
def encrypt(m, e, n):
    return quickpower(m, e ,n)

def decrypt(c, d, n):
    return quickpower(c, d, n)
    
    
if __name__=='__main__':
    import time
    start = time.perf_counter()
    p, q = select_pq(100,999)
    n = p*q
    fn = (p-1) * (q-1)
    e = select_e(fn)
    d = select_d(e, fn)
    print(f"q:{q}, p:{p}, fn:{(p-1)*(q-1)}")
    print(f"e:{e}, d:{d}, n:{n}")
    print(f"{e * d % fn}")
    plain = 7456
    c = encrypt(plain, e, n)
    print(f"encrypt: {plain}  -> {c}")
    c_plain = decrypt(c, d, n)
    print(f"decrypt: {c}  -> {c_plain}")
    end = time.perf_counter()
    print(f"performance: {end-start}s")